import type { KeyObject } from 'node:crypto';
import { randomToken } from '../utils/crypto.util.js';
import { durationOr, toMs } from '../utils/duration.util.js';
import type { Duration } from '../interfaces/duration.interface.js';
import type { JwsAlgorithm, JwtClaims } from '../interfaces/jwt.interface.js';
import type { JwtSignerOptions } from '../interfaces/jwt-options.interface.js';
import { algorithmFor, assertSigningKey, signJws, toKeyObject, unsupportedKeyError, warnShortSecret } from './jws.util.js';

/**
 * Issues signed JWTs. Adds `iat`, `exp`, `jti` and the configured
 * `iss`/`aud`; callers pass `sub` and custom claims. The module's
 * `accessToken` option configures the one `TokenService` uses; construct
 * others directly.
 */
export class JwtSigner {
  private readonly key: KeyObject;
  private readonly alg: JwsAlgorithm;

  /** Throws a `TypeError` for a key that cannot sign, or an invalid `ttl`. */
  constructor(private readonly options: JwtSignerOptions) {
    this.key = toKeyObject(options.key);
    const alg = options.alg ?? algorithmFor(this.key);
    if (!alg) {
      throw unsupportedKeyError(this.key, 'JwtSigner');
    }

    assertSigningKey(alg, this.key, 'JwtSigner', { allowShortSecret: options.allowShortSecret });
    if (options.allowShortSecret) {
      warnShortSecret(alg, this.key, 'JwtSigner');
    }
    this.alg = alg;
    toMs(options.ttl ?? 0); // an invalid duration fails here, not at the first sign()
  }

  sign(claims: JwtClaims, { ttl }: { ttl?: Duration } = {}): string {
    const iat = Math.floor((this.options.now?.() ?? Date.now()) / 1000);
    const lifetime = Math.floor(durationOr(ttl ?? this.options.ttl, '15m') / 1000);
    const payload: JwtClaims = {
      ...(this.options.issuer !== undefined && { iss: this.options.issuer }),
      ...(this.options.audience !== undefined && { aud: this.options.audience }),
      jti: randomToken(16),
      ...claims,
      iat,
      exp: iat + lifetime,
    };

    return signJws(
      { alg: this.alg, typ: this.options.type ?? 'JWT', ...(this.options.kid && { kid: this.options.kid }) },
      payload,
      this.key,
      { allowShortSecret: this.options.allowShortSecret },
    );
  }
}
