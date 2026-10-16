import { createHash } from 'node:crypto';
import { randomToken, safeEqual, sha256 } from '../utils/crypto.util.js';
import { durationOr } from '../utils/duration.util.js';
import { JwksClient } from '../jwt/jwks.client.js';
import { JwtError } from '../errors/jwt.error.js';
import type { JwtClaims } from '../interfaces/jwt.interface.js';
import { JwtVerifier } from '../jwt/jwt-verifier.service.js';
import type { OAuthTokens, OidcProfile, OidcProviderConfig } from '../interfaces/oidc-provider.interface.js';
import { OidcError } from '../errors/oidc.error.js';
import type { OidcTransaction, OidcClientOptions } from '../interfaces/oidc.interface.js';

interface Endpoints {
  issuer?: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  authorization_response_iss_parameter_supported?: boolean;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Only https, except loopback http (local IdPs and tests). The URLs come from the provider's
 * discovery document or the app's configuration, never from the request: a bad one is a
 * misconfiguration (`unavailable`, a 502), not a failed sign-in. Nor does this keep a fetch off
 * the app's own network: an issuer that customers enter themselves is the app's to check
 * against the providers it supports, before it stores it.
 */
function assertSecureUrl(value: string | undefined, what: string): string {
  let url: URL;
  try {
    url = new URL(value ?? '');
  } catch {
    throw new OidcError(`${what} is not a URL`, 'unavailable');
  }

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    throw new OidcError(`${what} must use https`, 'unavailable');
  }
  return url.toString();
}

/** A request to the provider: no redirects, a 10 s timeout, and a network failure as an outage. */
async function send(options: OidcClientOptions, url: string, init: RequestInit) {
  try {
    return await (options.fetch ?? fetch)(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10_000) });
  } catch (error) {
    throw new OidcError(`${new URL(url).host} is unreachable (${(error as Error).message})`, 'unavailable');
  }
}

/**
 * What the clients of one `OidcService` share: discovery documents, by
 * issuer, and key sets, by URI. Neither depends on the client id or secret,
 * so a client made anew for each login (`oidc.providers` as a function)
 * still fetches them once per TTL, and the key set's cooldown still holds.
 */
export class OidcMetadataCache {
  private readonly documents = new Map<string, { value: Promise<Endpoints>; at: number }>();
  private readonly keySets = new Map<string, JwksClient>();

  constructor(private readonly options: OidcClientOptions = {}) {}

  /** The discovery document of `issuer`, as published: the endpoints a config overrides are its own to merge. */
  document(issuer: string): Promise<Endpoints> {
    const ttl = durationOr(this.options.discoveryTtl, '1h');
    let cached = this.documents.get(issuer);
    if (!cached || this.now() - cached.at >= ttl) {
      const entry = { value: this.discover(issuer), at: this.now() };
      this.documents.set(issuer, entry);
      // Retry next time, unless a later fetch has taken its place.
      entry.value.catch(() => this.documents.get(issuer) === entry && this.documents.delete(issuer));
      cached = entry;
    }

    return cached.value;
  }

  /** The key set at `uri`, an https URL. */
  jwks(uri: string): JwksClient {
    let jwks = this.keySets.get(uri);
    if (!jwks) {
      jwks = new JwksClient(uri, { ...this.options.jwks, fetch: this.options.fetch, now: this.options.now });
      this.keySets.set(uri, jwks);
    }

    return jwks;
  }

  private async discover(issuer: string): Promise<Endpoints> {
    const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
    const response = await send(this.options, assertSecureUrl(url, 'issuer'), { headers: { accept: 'application/json' } });
    if (!response.ok) {
      throw new OidcError(`discovery failed (${response.status})`, 'unavailable');
    }

    const doc = (await response.json().catch(() => ({}))) as Endpoints;
    // OIDC Discovery §4.3: the document must name exactly the issuer we asked.
    if (doc.issuer !== issuer) {
      throw new OidcError('discovery issuer mismatch', 'unavailable');
    }

    return doc;
  }

  private now() {
    return this.options.now?.() ?? Date.now();
  }
}

/**
 * One OAuth 2.0 / OpenID Connect provider: authorization code flow with
 * PKCE (S256), `state` and `nonce`.
 *
 * Checks, in order: IdP error, `iss` response parameter (RFC 9207, mix-up
 * defence), token response shape, ID token signature (JWKS, RS256/ES256 by default,
 * alg/key binding), `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, and that
 * userinfo's `sub` matches the ID token's (OIDC Core §5.3.2).
 */
export class OidcClient {
  readonly kind: 'oidc' | 'oauth2';

  constructor(
    readonly name: string,
    private readonly config: OidcProviderConfig,
    private readonly options: OidcClientOptions = {},
    private readonly metadata = new OidcMetadataCache(options),
  ) {
    this.kind = config.kind ?? 'oidc';

    if (this.kind === 'oidc' && !config.issuer) {
      throw new Error(`OIDC provider '${name}' needs an issuer`);
    }
    if (this.kind === 'oauth2' && (!config.authorizationEndpoint || !config.tokenEndpoint || !config.profile)) {
      throw new Error(`OAuth 2.0 provider '${name}' needs authorizationEndpoint, tokenEndpoint and profile()`);
    }
  }

  /**
   * The provider's authorization URL, the transaction to store, and the
   * browser binding for the transaction cookie. `state` is the SHA-256 of
   * `binding`: the state travels in URLs (access logs, history, the error
   * page of a failed callback), so it must not be what the cookie holds, or
   * whoever reads a callback URL could redeem it from any client.
   */
  async authorizationRequest(redirectUri: string, redirectTo?: string, ttlMs = 600_000) {
    const endpoints = await this.endpoints();
    const now = this.now();
    const binding = randomToken();
    const transaction: OidcTransaction = {
      state: sha256(binding),
      provider: this.name,
      codeVerifier: randomToken(),
      ...(this.kind === 'oidc' && { nonce: randomToken() }),
      ...(redirectTo && { redirectTo }),
      createdAt: new Date(now),
      expiresAt: new Date(now + ttlMs),
    };

    const url = new URL(endpoints.authorization_endpoint);
    const params: Record<string, string> = {
      ...this.config.authorizationParams,
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope: (this.config.scopes ?? ['openid', 'email', 'profile']).join(' '),
      state: transaction.state,
      code_challenge: createHash('sha256').update(transaction.codeVerifier).digest('base64url'),
      code_challenge_method: 'S256',
      ...(transaction.nonce && { nonce: transaction.nonce }),
    };

    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }

    return { url: url.toString(), transaction, binding };
  }

  /** Completes the flow. The caller has already matched `state` to the browser and loaded `transaction`. */
  async callback(
    params: Record<string, unknown>,
    transaction: OidcTransaction,
    redirectUri: string,
  ): Promise<{ profile: OidcProfile; tokens: OAuthTokens }> {
    if (typeof params.error === 'string') {
      throw new OidcError(`provider returned ${params.error}`, 'request');
    }
    if (typeof params.code !== 'string' || !params.code) {
      throw new OidcError('missing code', 'request');
    }

    const endpoints = await this.endpoints();
    if (this.kind === 'oidc') {
      if (params.iss !== undefined && params.iss !== endpoints.issuer) {
        throw new OidcError('issuer mismatch', 'request');
      }
      if (params.iss === undefined && endpoints.authorization_response_iss_parameter_supported) {
        throw new OidcError('missing iss', 'request');
      }
    }

    const tokens = await this.exchange(endpoints, params.code, transaction, redirectUri);
    const context = { provider: this.name, tokens, fetchJson: (url: string) => this.getJson(url, tokens.accessToken) };

    const userinfo = (url: string) => this.getJson(url, tokens.accessToken, 'userinfo endpoint');
    if (this.kind === 'oauth2') {
      const profile = endpoints.userinfo_endpoint ? await userinfo(endpoints.userinfo_endpoint) : {};
      return { profile: await this.config.profile!(profile, context), tokens };
    }

    if (!tokens.idToken) {
      throw new OidcError('missing id_token', 'verification');
    }

    const claims = await this.verifyIdToken(endpoints, tokens.idToken, transaction.nonce!);
    let merged: Record<string, unknown> = claims;
    let info: Record<string, unknown> | undefined;
    if (endpoints.userinfo_endpoint) {
      info = await userinfo(endpoints.userinfo_endpoint);
      if (info?.sub !== claims.sub) {
        throw new OidcError('userinfo subject mismatch', 'verification');
      }
      merged = { ...info, ...claims };
    }

    // The address and whether it is verified come as a pair, from one source: the ID token's, or
    // else userinfo's. `email_verified` in one says nothing about an `email` in the other.
    const addressed = typeof claims.email === 'string' ? claims : (info ?? {});
    const email = typeof addressed.email === 'string' ? addressed.email : undefined;

    return {
      profile: {
        provider: this.name,
        subject: claims.sub!,
        email,
        emailVerified: email !== undefined && addressed.email_verified === true,
        name: typeof merged.name === 'string' ? merged.name : undefined,
        picture: typeof merged.picture === 'string' ? merged.picture : undefined,
        claims: merged,
      },
      tokens,
    };
  }

  private async verifyIdToken(endpoints: Endpoints, idToken: string, nonce: string): Promise<JwtClaims> {
    const verifier = new JwtVerifier({
      jwks: this.metadata.jwks(assertSecureUrl(endpoints.jwks_uri, 'jwks_uri')),
      algorithms: this.config.idTokenAlgorithms ?? ['RS256', 'ES256'],
      issuer: endpoints.issuer,
      audience: this.config.clientId,
      required: ['exp', 'iat', 'sub'],
      clockTolerance: this.options.clockTolerance ?? '30s',
      now: this.options.now,
    });

    let claims: JwtClaims;
    try {
      claims = await verifier.verify(idToken);
    } catch (error) {
      if (error instanceof JwtError) {
        throw new OidcError(`id_token ${error.message}`, 'verification');
      }
      // The provider's key set could not be loaded: an outage (502), as any other of the provider's.
      throw new OidcError((error as Error).message, 'unavailable');
    }

    if (typeof claims.sub !== 'string' || !claims.sub) {
      throw new OidcError('id_token without subject', 'verification');
    }
    const audiences = ([] as unknown[]).concat(claims.aud);
    if ((audiences.length > 1 || claims.azp !== undefined) && claims.azp !== this.config.clientId) {
      throw new OidcError('id_token azp mismatch', 'verification');
    }
    if (typeof claims.nonce !== 'string' || !safeEqual(claims.nonce, nonce)) {
      throw new OidcError('id_token nonce mismatch', 'verification');
    }

    return claims;
  }

  private async exchange(
    endpoints: Endpoints,
    code: string,
    transaction: OidcTransaction,
    redirectUri: string,
  ): Promise<OAuthTokens> {
    const method =
      this.config.tokenEndpointAuthMethod ?? (this.config.clientSecret ? 'client_secret_basic' : 'none');

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      code_verifier: transaction.codeVerifier,
    });
    const headers: Record<string, string> = {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
    };

    if (method === 'client_secret_basic') {
      // RFC 6749 §2.3.1: form-encode each part before base64.
      const id = encodeURIComponent(this.config.clientId);
      const secret = encodeURIComponent(this.config.clientSecret ?? '');
      headers.authorization = `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;
    } else {
      body.set('client_id', this.config.clientId);
      if (method === 'client_secret_post') {
        body.set('client_secret', this.config.clientSecret ?? '');
      }
    }

    const response = await this.request(endpoints.token_endpoint, { method: 'POST', headers, body });
    const json = (await response.json().catch(() => undefined)) as Record<string, unknown> | undefined;
    const error = typeof json?.error === 'string' ? json.error : undefined;
    if (response.status >= 500 && !error) {
      throw new OidcError(`token endpoint unavailable (${response.status})`, 'unavailable');
    }
    if (!response.ok || !json || error) {
      throw new OidcError(`token endpoint rejected the code (${error ?? response.status})`, 'verification');
    }
    if (typeof json.access_token !== 'string' || String(json.token_type).toLowerCase() !== 'bearer') {
      throw new OidcError('malformed token response', 'verification');
    }

    return {
      accessToken: json.access_token,
      ...(typeof json.refresh_token === 'string' && { refreshToken: json.refresh_token }),
      ...(typeof json.id_token === 'string' && { idToken: json.id_token }),
      ...(typeof json.expires_in === 'number' && { expiresIn: json.expires_in }),
      ...(typeof json.scope === 'string' && { scope: json.scope }),
    };
  }

  private async endpoints(): Promise<Endpoints> {
    if (this.kind === 'oauth2') {
      return {
        authorization_endpoint: assertSecureUrl(this.config.authorizationEndpoint, 'authorization_endpoint'),
        token_endpoint: assertSecureUrl(this.config.tokenEndpoint, 'token_endpoint'),
        ...(this.config.userinfoEndpoint && {
          userinfo_endpoint: assertSecureUrl(this.config.userinfoEndpoint, 'userinfo_endpoint'),
        }),
      };
    }

    const doc = await this.metadata.document(this.config.issuer!);
    return {
      ...doc,
      authorization_endpoint: assertSecureUrl(this.config.authorizationEndpoint ?? doc.authorization_endpoint, 'authorization_endpoint'),
      token_endpoint: assertSecureUrl(this.config.tokenEndpoint ?? doc.token_endpoint, 'token_endpoint'),
      userinfo_endpoint: (this.config.userinfoEndpoint ?? doc.userinfo_endpoint) && assertSecureUrl(this.config.userinfoEndpoint ?? doc.userinfo_endpoint, 'userinfo_endpoint'),
      jwks_uri: this.config.jwksUri ?? doc.jwks_uri,
    };
  }

  private async getJson(url: string, accessToken: string, what?: string): Promise<any> {
    const target = new URL(assertSecureUrl(url, 'API url'));
    // Errors reach responses and logs: name the host and path, never a query that may carry secrets.
    const name = what ?? `${target.host}${target.pathname}`;
    const response = await this.request(target.toString(), {
      headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
    });

    if (response.status >= 500) {
      throw new OidcError(`${name} unavailable (${response.status})`, 'unavailable');
    }
    if (!response.ok) {
      throw new OidcError(`${name} answered ${response.status}`, 'verification');
    }

    return response.json();
  }

  private request(url: string, init: RequestInit) {
    return send(this.options, url, init);
  }

  private now() {
    return this.options.now?.() ?? Date.now();
  }
}
