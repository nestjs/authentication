import type { Duration } from './duration.interface.js';

/**
 * Supported JWS algorithms (RFC 7518 §3.1). EdDSA means Ed25519 only: Ed448
 * is rejected (untested here, and rare in practice). PS256/384/512 take an
 * RSA key, as a JWKS publishes it; Node's `rsa-pss` key type is rejected.
 */
export type JwsAlgorithm =
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'EdDSA';

export interface JwtClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [claim: string]: unknown;
}

export interface ClaimRules {
  /**
   * Accepted `iss` values, compared exactly: no case folding, trailing
   * slash or prefix match. A list is for an identity provider that issues
   * under more than one name: Google signs ID tokens as either
   * `https://accounts.google.com` or `accounts.google.com`. A token without
   * `iss` is rejected.
   */
  issuer?: string | readonly string[];
  /**
   * Accepted `aud` values. `false` accepts any audience, for tokens that
   * carry none (check the claim that names your client in `validate()`).
   */
  audience?: string | string[] | false;
  /**
   * Leeway for `exp`, `nbf` and `iat`. Default `0`, right for the app's own
   * tokens. Set it (`'30s'`) for another issuer's: a clock a second ahead
   * would otherwise issue tokens "in the future".
   */
  clockTolerance?: Duration;
  /** Reject tokens issued longer ago than this (needs `iat`). */
  maxAge?: Duration;
  /** Claims that must be present. `exp` is required by default. */
  required?: string[];
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}
