import type { AuthenticationTypes } from '../index.js';

export interface IssueTokensOptions {
  /**
   * Claims that describe the sign-in (`amr`, `auth_time`, …): this access
   * token and every one `refresh()` mints carry them. Keep roles and other
   * facts that can change out of them: they are fixed for the family's life.
   * The service owns the `amr` values that mean a second factor (`mfa`,
   * `otp`, `hwk`): it adds `mfa` itself once a code was verified, and drops
   * them from `claims.amr` with a warning (the rest, `pwd`, `sso`, is kept).
   */
  claims?: Record<string, unknown>;
  /** How the user proved who they are, recorded on the `sign-in` event: `password`, `magic-link`. */
  method?: string;
  /**
   * The code the client sent for a user with a confirmed authenticator: a
   * TOTP `code` or a `recoveryCode`. Ignored for other users.
   */
  secondFactor?: { code?: string; recoveryCode?: string };
}

/**
 * What `TokenService.issue()` returns with `refreshToken: false`: an access
 * token alone, which the client replaces by signing in again.
 */
export interface AccessTokenResult {
  /** A JWT signed with the `accessToken` options. */
  accessToken: string;
  /** Seconds until the access token expires (OAuth's `expires_in`). */
  expiresIn: number;
}

/** What a token endpoint returns to a client that signed in. */
export interface TokenPair extends AccessTokenResult {
  /** Opaque, single use: `refresh()` exchanges it for a new pair. */
  refreshToken: string;
}

/**
 * What `TokenService.issue()` returns: a {@link TokenPair}, or, for an app
 * that declared `refreshTokens: false` on `AuthenticationTypes` (to go with
 * the `refreshToken: false` option), an {@link AccessTokenResult}:
 *
 * ```ts
 * declare module '@nestjs/authentication' {
 *   interface AuthenticationTypes {
 *     refreshTokens: false;
 *   }
 * }
 * ```
 *
 * The declaration is what the compiler sees; the option is what runs. An
 * app that sets the option without the declaration gets no `refreshToken`
 * at run time, typed as a string, and `refresh()` throws on it.
 */
export type IssuedTokens<Types = AuthenticationTypes> = Types extends { refreshTokens: false } ? AccessTokenResult : TokenPair;
