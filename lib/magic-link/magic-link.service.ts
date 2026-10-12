import { Inject, Injectable, Optional } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { firstHeader } from '../utils/auth-state.util.js';
import { AuthenticationScope } from '../context/authentication-scope.service.js';
import { AuthenticationRegistry } from '../services/authentication-registry.service.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { TOKEN_PATTERN, randomToken, safeEqual, safeRedirectPath, sha256 } from '../utils/crypto.util.js';
import { durationOr, hasExpired } from '../utils/duration.util.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import type { AuthenticationMagicLinkRefusedEvent } from '../events/authentication-events.interface.js';
import { requireUrlOption } from '../utils/options.util.js';
import { defaultCookieName, readCookie, serializeCookie } from '../session/cookies.util.js';
import type { IssuedSession } from '../interfaces/session.interface.js';
import { SignInService } from '../session/sign-in.service.js';
import type { MagicLinkOptions, MagicLinkRequest, CreatedMagicLink } from '../interfaces/magic-link.interface.js';
import { MagicLinkError } from '../errors/magic-link.error.js';
import { MagicLinkHandler } from './magic-link.handler.js';
import { isMailableEmail, normalizeEmail } from '../account/email.util.js';

/**
 * What the store keys a link by: the SHA-256 of its token, and of the secret
 * that binds it to a browser when it is bound (`bindToBrowser`), so the link
 * alone finds nothing.
 */
function linkId(token: string, binding: string | undefined): string {
  return sha256(binding === undefined ? token : `${token}.${binding}`);
}

/** Which link a browser's cookie is for: a public hint, computable from the link. */
function hintOf(token: string): string {
  return sha256(`nestjs-authentication magic-link hint ${token}`).slice(0, 12);
}

/**
 * How many links a browser holds the secrets of: a "resend" leaves the
 * links it requested before usable there, up to this many.
 */
const PENDING_LINKS = 5;
const HINT_PATTERN = /^[\w-]{12}$/;

/** A link this browser requested: its hint, and the secret it is stored under. */
type PendingLink = { hint: string; secret: string };

/** The links in the cookie, newest first: `<hint>.<secret>`, joined by `~`. Anything else is dropped. */
function readPending(value: string | undefined): PendingLink[] {
  return (value ?? '')
    .split('~')
    .map((pair) => pair.split('.'))
    .filter(([hint, secret, ...rest]) => HINT_PATTERN.test(hint) && TOKEN_PATTERN.test(secret ?? '') && !rest.length)
    .slice(0, PENDING_LINKS)
    .map(([hint, secret]) => ({ hint, secret }));
}

function writePending(links: PendingLink[]): string {
  return links.map(({ hint, secret }) => `${hint}.${secret}`).join('~');
}

/**
 * Passwordless sign-in links: 256-bit single-use tokens, stored hashed,
 * short-lived, and bound to the browser that requested them.
 *
 * Point the link at a page that POSTs the token back: mail scanners and
 * link previews follow GET links, and would burn (or use) the token.
 *
 * Like `OidcService`, the service binds each link to the browser that
 * requested it: `create()` refuses a request from another origin (another
 * site's page must not start a link here), and sets an `HttpOnly`,
 * `SameSite=Lax` cookie, `__Host-magic_link_tx`, holding a secret that no
 * link carries; the store keys the link by the token and that secret
 * together, so `consume()` finds it only with the cookie. The cookie holds
 * the secrets of the last five links the browser requested, so a "resend"
 * leaves the link before it usable there. The `__Host-`
 * prefix keeps sibling subdomains from planting one. So the link's page
 * must be on the same site as the API, as the session cookie requires
 * anyway, and a link forwarded to another browser or device, or read from
 * a log, is refused there while it stays usable where it was requested.
 * See `magicLink.bindToBrowser`.
 */
@Injectable()
export class MagicLinkService {
  private readonly options?: MagicLinkOptions;
  private readonly ttl: number;
  private readonly bindToBrowser: boolean;
  private readonly txCookieName: string;

  constructor(
    private readonly storage: AuthenticationStorage,
    private readonly registry: AuthenticationRegistry,
    private readonly signIn: SignInService,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { magicLink?: MagicLinkOptions },
    private readonly scope: AuthenticationScope = new AuthenticationScope(),
    @Optional() private readonly adapterHost?: HttpAdapterHost,
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
  ) {
    this.options = options?.magicLink;
    if (this.options) {
      requireUrlOption(this.options.url, 'magicLink.url', 'the page that receives the link');
    }
    this.ttl = durationOr(this.options?.ttl, '15m');
    this.bindToBrowser = this.options?.bindToBrowser !== false;
    this.txCookieName = defaultCookieName('magic_link_tx', this.options?.cookie);
  }

  /**
   * Creates a link and hands it to `MagicLinkHandler.send()`. The token is
   * not returned. Called from an HTTP handler, it sets the transaction
   * cookie on the response (see `bindToBrowser`); the returned `cookie` is
   * that `Set-Cookie` value, for callers outside HTTP. A request from another
   * origin than the app's own and `session.trustedOrigins` gets a
   * `ForbiddenException`, as `SignInService.signIn()` does. An `email` no
   * mail should go to (missing, blank, without `@`, over 254 characters, or
   * with whitespace or control characters) creates and sends nothing, and
   * gets the same answer, like `PasswordResetService.request()`.
   */
  async create(email: string, { redirectTo }: { redirectTo?: string } = {}): Promise<CreatedMagicLink> {
    const { options, handler } = this.feature();
    // The cookie binds the link to this browser: another site's page must not get one set here for
    // an address its author reads (login CSRF), whatever the request asks for.
    this.signIn.refuseCrossOrigin(this.scope.exchange()?.request);

    const now = this.now();
    const expiresAt = new Date(now + this.ttl);

    const normalized = typeof email === 'string' ? normalizeEmail(email) : '';
    if (!isMailableEmail(normalized)) {
      return { expiresAt };
    }

    const token = randomToken();
    const binding = this.bindToBrowser ? randomToken() : undefined;
    const safe = safeRedirectPath(redirectTo);
    await this.storage.magicLinks.saveMagicLink({
      id: linkId(token, binding),
      email: normalized,
      createdAt: new Date(now),
      expiresAt,
      ...(safe && { redirectTo: safe }),
    });

    let cookie: string | undefined;
    if (binding) {
      // The links this browser requested before stay usable here, the oldest dropped past the cap.
      const hint = hintOf(token);
      const before = readPending(this.pendingCookie(this.scope.exchange()?.request)).filter((link) => link.hint !== hint);
      cookie = this.txCookie(writePending([{ hint, secret: binding }, ...before].slice(0, PENDING_LINKS)), this.ttl / 1000);
      this.setCookie(cookie);
    }

    const url = new URL(options.url);
    url.searchParams.set('token', token);
    await handler.send({ email: normalized, url: url.toString(), expiresAt });

    return { expiresAt, ...(cookie && { cookie }) };
  }

  /**
   * Burns the token, asks `MagicLinkHandler.resolveUser()` for the user, and
   * signs them in on this browser through `SignInService`, which sets the
   * cookie. `null` for unknown, used or expired tokens and for addresses
   * the handler refuses, one answer for all of them. A link this browser
   * did not request (see `bindToBrowser`) throws {@link MagicLinkError}
   * instead, before anything is looked up or burned: the module answers it
   * with a 401 that tells the customer where to open the link. Each
   * refusal is a `magic-link-refused` event with its reason. Outside an
   * HTTP handler, pass the `request` that carries the cookie.
   */
  async consume(
    token: string,
    { request }: { request?: MagicLinkRequest } = {},
  ): Promise<(IssuedSession & { redirectTo?: string }) | null> {
    const { handler } = this.feature();
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
      return this.refuse('unknown');
    }

    let binding: string | undefined;
    let pending: PendingLink[] = [];
    let link: PendingLink | undefined;
    if (this.bindToBrowser) {
      pending = readPending(this.pendingCookie(request ?? this.scope.exchange()?.request));
      // The hint names a link this browser requested; anyone holding the link can compute it, so it
      // only tells a link opened elsewhere from a bad one. The secret, which no link carries, is what
      // the link is stored under: a leaked or forwarded link finds nothing without it. On a refusal
      // here the cookie stays (it holds the links this browser did request), and nothing is looked
      // up: a link was presented, not proved.
      const hint = hintOf(token);
      link = pending.find((candidate) => safeEqual(candidate.hint, hint));
      if (!link) {
        this.events.emit({ type: 'magic-link-refused', reason: 'not-this-browser' });
        throw new MagicLinkError();
      }
      binding = link.secret;
    }

    const record = await this.storage.magicLinks.consumeMagicLink(linkId(token, binding));
    // This link is settled either way: its secret goes, and the cookie with it when it held no other.
    const rest = writePending(pending.filter((candidate) => candidate !== link));
    this.setCookie(this.txCookie(rest, rest ? this.ttl / 1000 : 0));

    if (!record) {
      return this.refuse('unknown');
    }
    if (hasExpired(record.expiresAt, this.now())) {
      return this.refuse('expired', record.email);
    }
    const user = await handler.resolveUser(record.email);
    if (!user) {
      return this.refuse('refused', record.email);
    }
    // The link proved the address it was sent to, and signs in only the account whose address that
    // is: a lookup that folds accents or ignores dots would otherwise hand `victim@exämple.com`'s
    // mailbox the account of `victim@example.com`.
    if (typeof user.email !== 'string') {
      throw new TypeError(
        'MagicLinkHandler.resolveUser() must return the account’s stored `email` with its `id`: the link signs in ' +
          'only the account whose address it was sent to.',
      );
    }
    if (normalizeEmail(user.email) !== record.email) {
      return this.refuse('refused', record.email);
    }

    const issued = await this.signIn.signIn(user.id, { method: 'magic-link' });
    return { ...issued, redirectTo: record.redirectTo };
  }

  /** The options and the handler; the module refuses to start with one and not the other. */
  private feature(): { options: MagicLinkOptions; handler: MagicLinkHandler } {
    const handler = this.registry.handler('magicLink');
    if (!this.options || !handler) {
      throw new Error(
        'MagicLinkService: magic links are not enabled. Configure `magicLink` in the AuthenticationModule options, and ' +
          "register a MagicLinkHandler: `registry.registerHandler('magicLink', this)`.",
      );
    }
    return { options: this.options, handler };
  }

  /** The generic answer: which refusal it was is told only by the event. */
  private refuse(reason: Exclude<AuthenticationMagicLinkRefusedEvent['reason'], 'not-this-browser'>, email?: string): null {
    this.events.emit({ type: 'magic-link-refused', reason, ...(email && { email }) });
    return null;
  }

  private pendingCookie(request: MagicLinkRequest | undefined): string | undefined {
    return readCookie(firstHeader(request?.headers, 'cookie'), this.txCookieName);
  }

  private txCookie(value: string, maxAge: number): string {
    return serializeCookie(this.txCookieName, value, { ...this.options?.cookie, sameSite: 'lax', maxAge });
  }

  private setCookie(cookie: string) {
    if (!this.bindToBrowser) {
      return;
    }
    const response = this.scope.exchange()?.response;
    if (response) {
      this.adapterHost?.httpAdapter?.appendHeader(response, 'Set-Cookie', cookie);
    }
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}
