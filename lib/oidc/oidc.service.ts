import {
  BadGatewayException,
  BadRequestException,
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  NotFoundException,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { AuthenticationScope } from '../context/authentication-scope.service.js';
import { AuthenticationRegistry } from '../services/authentication-registry.service.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { safeEqual, safeRedirectPath, sha256 } from '../utils/crypto.util.js';
import { durationOr, hasExpired } from '../utils/duration.util.js';
import { requireOption } from '../utils/options.util.js';
import { defaultCookieName, readCookie, serializeCookie } from '../session/cookies.util.js';
import { SessionService } from '../session/session.service.js';
import { SignInService } from '../session/sign-in.service.js';
import type { OidcTransaction } from '../interfaces/oidc.interface.js';
import { OidcError } from '../errors/oidc.error.js';
import type { OidcProviderConfig } from '../interfaces/oidc-provider.interface.js';
import type { OidcOptions, OidcRequest, OidcRedirect, OidcStartOptions } from '../interfaces/oidc.interface.js';
import { OidcClient } from './oidc.client.js';
import { OidcAccountResolver } from './oidc-account.resolver.js';

type Headers = Record<string, string | string[] | undefined>;

const header = (headers: Headers, name: string) => {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
};

/**
 * OpenID Connect sign-in, behind two routes of your own: a login route that
 * redirects to the provider, and the callback route it sends the browser
 * back to. Called from an HTTP handler, each method reads the request and
 * sets its cookies on the response, on Express and Fastify alike:
 *
 * ```ts
 * @Public()
 * @Controller('auth/oidc')
 * export class OidcController {
 *   constructor(private readonly oidc: OidcService) {}
 *
 *   @Get(':provider/login')
 *   @Redirect()
 *   login(@Param('provider') provider: string, @Query('redirectTo') redirectTo?: string, @Query('link') link?: string) {
 *     return this.oidc.start(provider, { redirectTo, link: link === 'true' });
 *   }
 *
 *   @Get(':provider/callback')
 *   @Redirect()
 *   callback(@Param('provider') provider: string, @Query() query: Record<string, string>) {
 *     return this.oidc.finish(provider, query);
 *   }
 * }
 * ```
 *
 * The transaction (PKCE verifier, nonce, return path) stays server-side,
 * keyed by `state`; the browser gets, in an `HttpOnly` cookie, the secret
 * whose SHA-256 is the `state`. The callback must present both, which binds
 * the response to the browser that started the login: another browser
 * cannot finish it (login CSRF), nor can whoever reads the callback URL in a
 * log or a history. `SameSite=Lax` lets the cookie through the IdP's
 * top-level redirect, and the `__Host-` prefix keeps sibling subdomains from
 * planting one.
 *
 * `start(provider, { link: true })` begins a link flow for the signed-in
 * user instead of a sign-in: the callback re-checks that the same session is
 * still live, hands `{ linkTo }` to the resolver, and keeps the session as
 * it is.
 */
@Injectable()
export class OidcService {
  private readonly clients = new Map<string, OidcClient>();
  private readonly options?: OidcOptions;
  private readonly transactionTtl: number;
  private readonly txCookieName: string;

  constructor(
    private readonly storage: AuthenticationStorage,
    private readonly registry: AuthenticationRegistry,
    private readonly signIn: SignInService,
    private readonly sessions: SessionService,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { oidc?: OidcOptions },
    private readonly scope: AuthenticationScope = new AuthenticationScope(),
    @Optional() private readonly adapterHost?: HttpAdapterHost,
  ) {
    this.options = options?.oidc;
    if (this.options) {
      if (typeof this.options.callbackUrl !== 'function') {
        assertCallbackUrl(this.options.callbackUrl);
      }
      assertProviderCredentials(this.options.providers);
    }

    this.transactionTtl = durationOr(this.options?.transactionTtl, '10m');
    this.txCookieName = defaultCookieName('oidc_tx', this.options?.cookie);
  }

  client(name: string): OidcClient {
    const { options } = this.feature();
    const config = Object.hasOwn(options.providers, name) ? options.providers[name] : undefined;
    if (!config) {
      throw new NotFoundException();
    }

    let client = this.clients.get(name);
    if (!client) {
      client = new OidcClient(name, config, options);
      this.clients.set(name, client);
    }

    return client;
  }

  /**
   * Starts a login: stores the transaction, sets its cookie, and returns
   * the provider's authorization URL. 404 for a provider that isn't
   * configured; 401 for a link flow without a signed-in session.
   */
  async start(provider: string, { redirectTo, link = false, request }: OidcStartOptions = {}): Promise<OidcRedirect> {
    const exchange = this.scope.exchange();
    const req = request ?? exchange?.request ?? { headers: {} };

    let linking: OidcTransaction['link'];
    if (link) {
      // A link attaches whatever account the provider has signed in on this browser: never at the
      // bidding of another site's page (a top-level navigation carries the Lax session cookie).
      if (header(req.headers, 'sec-fetch-site') === 'cross-site') {
        throw new ForbiddenException('Cross-site link refused');
      }
      const session = await this.currentSession(req);
      if (!session) {
        throw new UnauthorizedException('sign in to link an account');
      }
      linking = { userId: session.userId, sessionId: session.id };
    }

    const { url, transaction, binding } = await this.client(provider)
      .authorizationRequest(await this.callbackUrl(provider, req), safeRedirectPath(redirectTo), this.transactionTtl)
      .catch(toHttp);
    await this.storage.oidcStates.saveOidcState({ ...transaction, ...(linking && { link: linking }) });
    return this.redirect(exchange?.response, url, [this.txCookie(binding, this.transactionTtl / 1000)]);
  }

  /**
   * Completes a login on the callback route, and returns where to send the
   * browser: the login's `redirectTo`, else `redirectAfterLogin`. A sign-in
   * goes through `SignInService`, which sets the session cookie on the
   * response; the transaction cookie is cleared.
   */
  async finish(provider: string, query: Record<string, unknown>, { request }: { request?: OidcRequest } = {}): Promise<OidcRedirect> {
    const { options, resolver } = this.feature();
    const exchange = this.scope.exchange();
    const req = request ?? exchange?.request ?? { headers: {} };

    // The cookie holds the secret whose SHA-256 is the state. The state travels in URLs, the
    // secret never does: a callback URL read from a log is useless without this browser's cookie.
    const state = query.state;
    const bound = readCookie(header(req.headers, 'cookie'), this.txCookieName);
    if (typeof state !== 'string' || !bound || !safeEqual(sha256(bound), state)) {
      throw new BadRequestException('state mismatch');
    }

    const transaction = await this.storage.oidcStates.consumeOidcState(state);
    if (!transaction || transaction.provider !== provider || hasExpired(transaction.expiresAt, this.now())) {
      throw new BadRequestException('unknown or expired login');
    }

    // Asked again rather than stored with the login: the cookie keeps the callback on the login's host,
    // and a function that answers otherwise gets the code refused by the provider, not accepted.
    const callbackUrl = await this.callbackUrl(provider, req);
    const result = await this.client(provider).callback(query, transaction, callbackUrl).catch(toHttp);

    const location = transaction.redirectTo ?? options.redirectAfterLogin ?? '/';
    if (transaction.link) {
      // The session that asked to link must still be the one on this browser.
      const session = await this.currentSession(req);
      if (session?.id !== transaction.link.sessionId) {
        throw new UnauthorizedException('sign in to link an account');
      }

      const user = await resolver.resolveUser(result.profile, result.tokens, { linkTo: { id: session.userId } });
      if (!user || user.id !== session.userId) {
        throw new ForbiddenException('account not linked');
      }

      return this.redirect(exchange?.response, location, [this.txCookie('', 0)]);
    }

    const user = await resolver.resolveUser(result.profile, result.tokens, {});
    if (!user) {
      throw new ForbiddenException('account not allowed');
    }

    const issued = await this.signIn.signIn(user.id, { method: `oidc:${provider}` });
    // `signIn()` set the session cookie on the response itself; the caller outside HTTP needs it too.
    const { url } = this.redirect(exchange?.response, location, [this.txCookie('', 0)]);
    return { url, cookies: [issued.cookie, this.txCookie('', 0)] };
  }

  /** Sets the cookies (and `no-store`) on the HTTP response, if there is one. */
  private redirect(response: unknown, url: string, cookies: string[]): OidcRedirect {
    const adapter = this.adapterHost?.httpAdapter;
    if (response && adapter) {
      for (const cookie of cookies) {
        adapter.appendHeader(response, 'Set-Cookie', cookie);
      }
      adapter.setHeader(response, 'Cache-Control', 'no-store');
    }
    return { url, cookies };
  }

  /** The options and the resolver; the module refuses to start with one and not the other. */
  private feature(): { options: OidcOptions; resolver: OidcAccountResolver } {
    const resolver = this.registry.handler('oidc');
    if (!this.options || !resolver) {
      throw new Error(
        'OidcService: OpenID Connect is not enabled. Configure `oidc` in the AuthenticationModule options, and register ' +
          "an OidcAccountResolver: `registry.registerHandler('oidc', this)`.",
      );
    }
    return { options: this.options, resolver };
  }

  /** A fully signed-in session (second factor done, if any) on this request. */
  private async currentSession(request: OidcRequest) {
    const session = await this.sessions.validate(this.sessions.tokenFrom(request));
    return session && session.mfa !== 'pending' ? session : null;
  }

  /** `oidc.callbackUrl` for this request, with the provider's name in it. */
  private async callbackUrl(provider: string, request: OidcRequest) {
    const { callbackUrl } = this.feature().options;
    const url = typeof callbackUrl === 'function' ? await callbackUrl(request) : callbackUrl;
    if (typeof callbackUrl === 'function') {
      assertCallbackUrl(url, 'the `oidc.callbackUrl` function must return');
    }
    return url.replaceAll(':provider', encodeURIComponent(provider));
  }

  private txCookie(value: string, maxAge: number) {
    return serializeCookie(this.txCookieName, value, { ...this.options?.cookie, sameSite: 'lax', maxAge });
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}

/**
 * `oidc.callbackUrl`, checked at startup (or each URL its function returns,
 * when it returns it): an absolute http(s) URL.
 */
function assertCallbackUrl(value: unknown, must = '`oidc.callbackUrl` must be') {
  let url: URL | undefined;
  try {
    url = typeof value === 'string' ? new URL(value.replaceAll(':provider', 'provider')) : undefined;
  } catch {
    url = undefined;
  }

  if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:')) {
    throw new Error(
      `OidcService: ${must} the absolute URL of your callback route, with \`:provider\` where the ` +
        `provider's name goes, e.g. 'https://app.example.com/auth/oidc/:provider/callback'. Got ${JSON.stringify(value)}.`,
    );
  }
}

/**
 * `oidc.providers.<name>.clientId`, and `clientSecret` unless the provider
 * is a public client (`tokenEndpointAuthMethod: 'none'`), checked at
 * startup: an unset environment variable would otherwise turn a
 * confidential client into a public one, and fail at the token exchange.
 */
function assertProviderCredentials(providers: Record<string, OidcProviderConfig> | undefined) {
  requireOption(providers, 'oidc.providers', 'the providers users can sign in with, by name');
  for (const [name, config] of Object.entries(providers!)) {
    requireOption(config?.clientId, `oidc.providers.${name}.clientId`, 'the client id the provider issued');
    if (config.tokenEndpointAuthMethod !== 'none') {
      requireOption(
        config.clientSecret,
        `oidc.providers.${name}.clientSecret`,
        "the client secret the provider issued; a public client sets `tokenEndpointAuthMethod: 'none'` instead",
      );
    }
  }
}

/** An `OidcError` as the HTTP answer: 400 for a bad callback, 401 for a failed check, 502 for a provider that is down. */
function toHttp(error: unknown): never {
  if (!(error instanceof OidcError)) {
    throw error;
  }

  const Exception: new (message: string) => HttpException = {
    request: BadRequestException,
    verification: UnauthorizedException,
    unavailable: BadGatewayException,
  }[error.kind];
  throw new Exception(error.message);
}
