import type { AuthenticationTypes } from '../index.js';

/**
 * Maps a refresh-token family's claims to the successor's, given the
 * family's current claims and the `userId` it belongs to. Can be async, and
 * can throw to refuse the refresh without spending the token (the caller
 * sees whatever it threw). `amr`, `auth_time` and the registered JWT claims
 * (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) stay the family's own,
 * whatever is returned.
 */
export type RefreshClaimsMapper = (current: Record<string, unknown>, userId: string) => Record<string, unknown> | Promise<Record<string, unknown>>;

export interface RefreshTokenMapOptions {
  /** Replaces the family's claims with the mapper's result for every token minted from now on. */
  claims?: RefreshClaimsMapper;
}

export interface IssueTokensOptions {
  /**
   * Claims that describe the sign-in (`amr`, `auth_time`, …): this access
   * token and every one `refresh()` mints carry them. Keep roles and other
   * facts that can change out of them: they stay the same for the family's
   * life, unless a `claims` mapper passed to `refresh()` replaces them.
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
