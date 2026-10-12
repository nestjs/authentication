import type { CookieAttributes } from '../session/cookies.util.js';
import type { Duration } from './duration.interface.js';
import type { OidcProviderConfig } from './oidc-provider.interface.js';

export interface OidcTransaction {
  state: string;
  provider: string;
  nonce?: string;
  codeVerifier: string;
  redirectTo?: string;
  createdAt: Date;
  expiresAt: Date;
  /** Set for a link flow: the signed-in user (and their session id) who started it. */
  link?: { userId: string; sessionId: string };
}

export interface OidcClientOptions {
  fetch?: typeof fetch;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
  /** How long a discovery document is trusted. Default `'1h'`. */
  discoveryTtl?: Duration;
  /** Leeway for ID token time claims. Default `'30s'`. */
  clockTolerance?: Duration;
  /** The providers' key sets: see `JwksClient`. */
  jwks?: { cacheTtl?: Duration; cooldown?: Duration };
}

export interface OidcResolveContext {
  /**
   * Set when a signed-in user started the flow with `?link=true` ("connect
   * your Google account"): attach the identity to this user, and refuse
   * (throw, or return `null`) when it already belongs to someone else.
   * The user's session was re-checked on the callback.
   */
  linkTo?: { id: string };
}

export interface OidcOptions extends OidcClientOptions {
  /**
   * The public URL of your callback route, the redirect URI you register
   * with each provider. `:provider` is replaced by the provider's name:
   * `https://app.example.com/auth/oidc/:provider/callback`.
   *
   * An app served under several domains passes a function of the request
   * instead, called on the login and again on the callback: both must
   * answer the same URL, or the provider refuses the code. Check the host
   * against your own list of domains rather than echoing the header, and
   * register every URL it can answer with each provider. The transaction
   * cookie is bound to the host that set it, so a login finishes on the
   * domain where it started.
   */
  callbackUrl: string | ((request: OidcRequest) => string | Promise<string>);
  providers: Record<string, OidcProviderConfig>;
  /** Where to land after sign-in when the login had no `redirectTo`. Default `/`. */
  redirectAfterLogin?: string;
  /** Lifetime of a login between the redirect to the provider and the callback. Default `'10m'`. */
  transactionTtl?: Duration;
  /**
   * Attributes of the transaction cookie, `__Host-oidc_tx` (or `oidc_tx`
   * when they rule the prefix out). `secure` defaults to `true`;
   * `SameSite` is always `Lax`, which lets the cookie through the
   * provider's redirect back.
   */
  cookie?: CookieAttributes;
}

/** The HTTP request of a login or callback, as Express and Fastify provide it. */
export type OidcRequest = { headers: Record<string, string | string[] | undefined>; method?: string };

/**
 * Where to send the browser: return it from a handler decorated with
 * `@Redirect()`. `cookies` are the `Set-Cookie` values the service already
 * set on the HTTP response; send them yourself outside an HTTP handler.
 */
export interface OidcRedirect {
  url: string;
  cookies: string[];
}

export interface OidcStartOptions {
  /** A relative path to land on after signing in; anything else is ignored. */
  redirectTo?: unknown;
  /** Link the provider to the signed-in user ("connect your Google account") instead of signing in. */
  link?: boolean;
  /** The request, outside an HTTP handler (tests). Inside one, the service reads it. */
  request?: OidcRequest;
}
