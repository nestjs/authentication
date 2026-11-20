import type { KeyObject } from 'node:crypto';
import type { JwksClient } from '../jwt/jwks.client.js';
import type { Duration } from './duration.interface.js';
import type { ClaimRules, JwsAlgorithm } from './jwt.interface.js';

export interface JwksClientOptions {
  /** How long a fetched key set is trusted. Default `'10m'`. */
  cacheTtl?: Duration;
  /**
   * Minimum gap between refetches triggered by an unknown `kid`. Default
   * `'30s'`. Stops a flood of tokens with random `kid`s from turning into a
   * flood of requests to the IdP.
   */
  cooldown?: Duration;
  /** Request timeout. Default `'5s'`. */
  timeout?: Duration;
  fetch?: typeof fetch;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

export interface JwtVerifierOptions extends ClaimRules {
  /**
   * A static key: an HMAC secret (at least 32 bytes for HS256, or shorter with
   * `allowShortSecret`), or a public or
   * private key as a `KeyObject` or PEM text (a string or a `Buffer`). A
   * public key needs `issuer` and `audience`, as a `jwks` does: it is an
   * identity provider's, which signs the tokens of all its clients with it.
   * A JWK, or DER, is refused (read as bytes, it would be an HS256 secret):
   * pass `createPublicKey({ key: jwk, format: 'jwk' })`.
   */
  key?: KeyObject | string | Buffer;
  /**
   * A JWKS URL, or a shared {@link JwksClient}. Needs `issuer` and
   * `audience`: an identity provider's keys sign the tokens of every one of
   * its clients.
   */
  jwks?: string | JwksClient;
  /**
   * Accepted `alg` values. Defaults: `['HS256']` for a secret, `['RS256']`
   * for an RSA key, the curve's own (`ES256`, `ES384`, `ES512`) for an EC
   * key, `['EdDSA']` for an Ed25519 key, and `['RS256', 'ES256']` for a JWKS.
   * Others (`RS384`, `PS256`, `HS512`, …) are opted into here. `none` is
   * never accepted, and HS algorithms never with a JWKS.
   */
  algorithms?: JwsAlgorithm[];
  /** Required `typ` header, e.g. `at+jwt` (RFC 9068). Not checked by default. */
  type?: string;
  /**
   * Accept an HMAC `key` shorter than the algorithm's minimum (32 bytes for
   * HS256), for an existing secret other services also use. Anyone holding a
   * token can guess a short secret offline, so this logs a warning at
   * startup. Default `false`.
   */
  allowShortSecret?: boolean;
}

export interface JwtSignerOptions {
  /**
   * An HMAC secret (at least as long as the hash: 32, 48 or 64 bytes, or
   * shorter with `allowShortSecret`), or an
   * RSA, P-256, P-384, P-521 or Ed25519 private key: a `KeyObject`, or PEM
   * text (a string or a `Buffer`). A JWK, or
   * DER, is refused: pass `createPrivateKey({ key: jwk, format: 'jwk' })`.
   */
  key: KeyObject | string | Buffer;
  /**
   * Default: HS256 for a secret, RS256 for an RSA key, the curve's own for
   * an EC key, EdDSA for an Ed25519 key.
   */
  alg?: JwsAlgorithm;
  /** Published in the header so verifiers can pick the key from a JWKS. */
  kid?: string;
  issuer?: string;
  audience?: string | string[];
  /** Lifetime of a token. Default `'15m'`: access tokens should be short-lived. */
  ttl?: Duration;
  /** `typ` header. Default `JWT`; RFC 9068 access tokens use `at+jwt`. */
  type?: string;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
  /**
   * Accept an HMAC `key` shorter than the algorithm's minimum (32 bytes for
   * HS256), for an existing secret other services sign or verify with. Tokens
   * stay plain HS256 with that secret. Anyone holding a token can guess a
   * short secret offline, so this logs a warning at startup. Default `false`.
   */
  allowShortSecret?: boolean;
}

export interface JwtBearerProviderOptions extends JwtVerifierOptions {
  /** `realm` in the `WWW-Authenticate` challenge. Default `api`. */
  realm?: string;
}
