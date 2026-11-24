import { createPublicKey, type KeyObject } from 'node:crypto';
import { toMs } from '../utils/duration.util.js';
import { JwtError } from '../errors/jwt.error.js';
import type { JwsAlgorithm, JwtClaims } from '../interfaces/jwt.interface.js';
import type { JwtSignerOptions } from '../interfaces/jwt-options.interface.js';
import type { JwtVerifierOptions } from '../interfaces/jwt-options.interface.js';
import { JwksClient } from './jwks.client.js';
import {
  algorithmFor,
  assertKeyFits,
  decodeJws,
  isHmac,
  toKeyObject,
  unsupportedKeyError,
  validateClaims,
  verifySignature,
  warnShortSecret,
} from './jws.util.js';

/**
 * Verifies compact JWS tokens and their registered claims. `verify()`
 * throws {@link JwtError}; a configuration that could not verify anything
 * throws a `TypeError` in the constructor.
 */
export class JwtVerifier {
  private readonly key?: KeyObject;
  private readonly jwks?: JwksClient;
  readonly algorithms: JwsAlgorithm[];

  constructor(private readonly options: JwtVerifierOptions) {
    if (!!options.key === !!options.jwks) {
      throw new TypeError('JwtVerifier: pass exactly one of `key` or `jwks`.');
    }
    // A copy: a list changed after construction must not change which tokens verify.
    this.options = { ...options, issuer: acceptedIssuers(options.issuer) };

    let given: KeyObject | undefined;
    if (options.key) {
      given = toKeyObject(options.key);
      // A private key verifies with its public half, derived once.
      this.key = given.type === 'private' ? createPublicKey(given) : given;
    }
    if (options.jwks) {
      this.jwks = typeof options.jwks === 'string' ? new JwksClient(options.jwks) : options.jwks;
    }

    if (this.key) {
      const implied = algorithmFor(this.key);
      if (!implied) {
        throw unsupportedKeyError(this.key, 'JwtVerifier');
      }
      this.algorithms = options.algorithms ?? [implied];
      for (const alg of this.algorithms) {
        assertKeyFits(alg, this.key, 'JwtVerifier', { allowShortSecret: options.allowShortSecret });
        if (options.allowShortSecret) {
          warnShortSecret(alg, this.key, 'JwtVerifier');
        }
      }
      // A public key is someone else's, an identity provider's that signs every client's tokens with
      // it, as with a JWKS. A secret or a private key is the app's own (`verifierForSigner()`).
      if (given?.type === 'public') {
        requireIssuerAndAudience(options, 'public `key`');
      }
    } else {
      this.algorithms = options.algorithms ?? ['RS256', 'ES256'];
      // A JWKS publishes keys to everyone: an HMAC secret taken from one would let anyone sign.
      const hmac = this.algorithms.find(isHmac);
      if (hmac) {
        throw new TypeError(`JwtVerifier: ${hmac} cannot be combined with a JWKS.`);
      }
      requireIssuerAndAudience(options, '`jwks`');
    }

    // Invalid durations fail here, not at the first request.
    toMs(options.clockTolerance ?? 0);
    toMs(options.maxAge ?? 0);
  }

  async verify(token: string): Promise<JwtClaims> {
    const decoded = decodeJws(token);
    const { header } = decoded;
    const alg = header.alg as JwsAlgorithm;

    if (!this.algorithms.includes(alg)) {
      throw new JwtError('unsupported algorithm');
    }
    // RFC 7515 §4.1.11: extensions we do not understand must be rejected.
    if (header.crit !== undefined) {
      throw new JwtError('unsupported critical header');
    }
    if (this.options.type !== undefined && (typeof header.typ !== 'string' || mediaType(header.typ) !== mediaType(this.options.type))) {
      throw new JwtError('unexpected token type');
    }

    const key = this.key ?? (await this.jwks!.getKey(header));
    verifySignature(alg, key, decoded, { allowShortSecret: this.options.allowShortSecret });
    validateClaims(decoded.payload, this.options);

    return decoded.payload;
  }
}

/** Throws unless the tokens of a key the app does not own are pinned to their issuer and to the app. */
function requireIssuerAndAudience(options: JwtVerifierOptions, what: string) {
  if (options.issuer !== undefined && options.audience !== undefined) {
    return;
  }
  throw new TypeError(
    `JwtVerifier: a ${what} verifier needs \`issuer\` and \`audience\`. An identity provider signs tokens for ` +
      'all of its clients with the same keys, so without them tokens issued to other applications verify ' +
      'too. For tokens that carry no audience, pass `audience: false` and check the claim that names your ' +
      'client in `validate()`.',
  );
}

/**
 * The `issuer` option, checked and copied: a string, or a non-empty list of
 * non-empty strings. An empty list would reject every token; an entry that
 * is not a string, or is empty, is a configuration mistake (an unset
 * environment variable, a split on a trailing comma) that must not decide
 * which tokens verify.
 */
function acceptedIssuers(issuer: unknown): string | readonly string[] | undefined {
  if (issuer === undefined || typeof issuer === 'string') {
    return issuer;
  }
  // Copied before the check: `every()` skips the holes of a sparse array, which the copy fills with `undefined`.
  const list: unknown[] = Array.isArray(issuer) ? [...issuer] : [];
  if (list.length > 0 && list.every((value) => typeof value === 'string' && value !== '')) {
    return Object.freeze(list as string[]);
  }
  throw new TypeError('JwtVerifier: `issuer` must be a string or a non-empty array of non-empty strings.');
}

/**
 * A `typ` as RFC 7515 §4.1.9 compares it: without regard to case, and with
 * `application/` implied when it has no `/`, so `at+jwt` and
 * `application/at+jwt` are one type (RFC 9068 §4 accepts both).
 */
function mediaType(typ: string): string {
  const lower = typ.toLowerCase();
  return lower.includes('/') ? lower : `application/${lower}`;
}

/**
 * @internal A verifier for what a `JwtSigner` with these options issues:
 * the same secret, or the public half of its private key, with its
 * algorithm, issuer, audience and `typ`. `overrides` add rules (`maxAge`).
 */
export function verifierForSigner(
  signer: JwtSignerOptions,
  overrides: Omit<JwtVerifierOptions, 'key' | 'jwks'> = {},
): JwtVerifier {
  const key = toKeyObject(signer.key);
  const alg = signer.alg ?? algorithmFor(key);
  return new JwtVerifier({
    issuer: signer.issuer,
    audience: signer.audience,
    type: signer.type,
    now: signer.now,
    allowShortSecret: signer.allowShortSecret,
    ...(alg && { algorithms: [alg] }),
    ...overrides,
    // The signer's own key (a secret or a private key): its tokens are the app's.
    key,
  });
}
