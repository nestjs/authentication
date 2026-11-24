import {
  KeyObject,
  X509Certificate,
  constants,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  timingSafeEqual,
} from 'node:crypto';
import { Logger } from '@nestjs/common';
import { toMs } from '../utils/duration.util.js';
import type { JwsAlgorithm, JwtClaims, ClaimRules } from '../interfaces/jwt.interface.js';
import { JwtError } from '../errors/jwt.error.js';

/** The algorithms a public key verifies: the only ones a JWKS can serve (HS secrets are never published). */
export const ASYMMETRIC_ALGORITHMS: readonly JwsAlgorithm[] = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
];

type HashedAlgorithm = Exclude<JwsAlgorithm, 'EdDSA'>;

/** `HS384` → `sha384`: the digest every algorithm but EdDSA names in its last three digits. */
const hashOf = (alg: HashedAlgorithm) => `sha${alg.slice(2)}` as 'sha256' | 'sha384' | 'sha512';

/** The curve each ECDSA algorithm is bound to (RFC 7518 §3.4), by its OpenSSL name. */
const CURVES = { ES256: 'prime256v1', ES384: 'secp384r1', ES512: 'secp521r1' } as const;
/** The reverse: the one algorithm an EC key of each curve implies. Other curves (secp256k1, …) imply none. */
const CURVE_ALGORITHMS: Record<string, JwsAlgorithm> = { prime256v1: 'ES256', secp384r1: 'ES384', secp521r1: 'ES512' };

/** Raw r||s length: twice the curve's coordinate size (P-521's is 66 bytes, not 64). */
const ECDSA_SIGNATURE_BYTES = { ES256: 64, ES384: 96, ES512: 132 } as const;

export interface JwsHeader {
  alg: string;
  kid?: string;
  typ?: string;
  crit?: unknown;
  [key: string]: unknown;
}

const SEGMENT = /^[A-Za-z0-9_-]+$/;
const PEM = /-----BEGIN ([A-Z0-9 ]+)-----/g;

/**
 * A key from configuration. PEM text (a string or a `Buffer`: SPKI, PKCS#1,
 * PKCS#8, SEC1, or an X.509 certificate) is read as the key it encodes;
 * only other text is an HMAC secret. Read as a secret, a PEM public key
 * would let anyone who has it, which is everyone, sign HS256 tokens. So
 * would a JWK, or a key in DER (bytes, or base64 of them), which are refused:
 * import it with `createPublicKey({ key, format: 'jwk' })` (or `'der'`, or
 * `createPrivateKey`) and pass the `KeyObject`.
 */
export function toKeyObject(key: KeyObject | string | Buffer): KeyObject {
  if (key instanceof KeyObject) {
    return key;
  }

  const text = typeof key === 'string' ? key : key.toString('latin1');
  // Every block's label: `openssl ecparam -genkey` puts EC PARAMETERS before the private key, and
  // a bundle may put a certificate first.
  const labels = [...text.matchAll(PEM)].map((match) => match[1]);
  if (labels.length === 0) {
    if (isJwk(text)) {
      throw new TypeError(
        'The key is a JWK, which would be read as an HS256 secret. Import it and pass the KeyObject: ' +
          "`createPublicKey({ key: JSON.parse(jwk), format: 'jwk' })`, or `createPrivateKey` for a private key.",
      );
    }
    if (isEncodedKey(key)) {
      throw new TypeError(
        'The key is DER (binary, or base64 of it, as Keycloak shows `public_key`), which would be read as an ' +
          "HS256 secret. Pass PEM text, or the KeyObject: `createPublicKey({ key, format: 'der', type: 'spki' })`.",
      );
    }
    return createSecretKey(typeof key === 'string' ? Buffer.from(key) : key);
  }

  const label = labels.find((name) => name.includes('PRIVATE KEY')) ?? labels[0];
  try {
    return label.includes('PRIVATE KEY') ? createPrivateKey(key) : createPublicKey(key);
  } catch (error) {
    throw new TypeError(`Cannot read the PEM ${label.toLowerCase()}: ${(error as Error).message}`);
  }
}

/**
 * The algorithm a key implies: HS256 for a secret, RS256 for an RSA key (the
 * key does not name a hash or padding: PS and the longer hashes are opted
 * into with `alg`), and the curve's own for an EC key.
 */
export function algorithmFor(key: KeyObject): JwsAlgorithm | undefined {
  if (key.type === 'secret') {
    return 'HS256';
  }
  switch (key.asymmetricKeyType) {
    case 'rsa':
      return 'RS256';
    case 'ec':
      return CURVE_ALGORITHMS[key.asymmetricKeyDetails?.namedCurve ?? ''];
    case 'ed25519':
      return 'EdDSA';
    default:
      return undefined;
  }
}

/** The configuration error for a key no algorithm fits: an EC key names its curve, as EC keys of other curves are. */
export function unsupportedKeyError(key: KeyObject, owner: string): TypeError {
  const curve = key.asymmetricKeyType === 'ec' ? key.asymmetricKeyDetails?.namedCurve : undefined;
  return new TypeError(
    curve
      ? `${owner}: EC keys on ${curve} are not supported (use P-256, P-384 or P-521).`
      : `${owner}: ${key.asymmetricKeyType} keys are not supported.`,
  );
}

/** The minimum HMAC secret per algorithm: the hash's output size (RFC 7518 §3.2). */
const HMAC_SECRET_BYTES = { HS256: 32, HS384: 48, HS512: 64 } as const;

/** How strictly a key is checked against its algorithm. */
export interface KeyRules {
  /**
   * Accept an HMAC secret shorter than the hash's output (32, 48 or 64
   * bytes). For an existing secret that other services also sign or verify
   * with; anyone holding a token can guess a short secret offline.
   */
  allowShortSecret?: boolean;
}

/**
 * Whether `key` is appropriate for `alg`. This is the algorithm/key binding
 * that stops key-confusion attacks: an RSA public key can never be used as
 * an HMAC secret, a P-384 key never verifies ES256, and so on.
 */
export function keyFits(alg: JwsAlgorithm, key: KeyObject, { allowShortSecret = false }: KeyRules = {}): boolean {
  const details = key.asymmetricKeyDetails;
  switch (alg) {
    // A secret at least as long as the hash's output (RFC 7518 §3.2), unless the app opted into a
    // shorter one it already has (`allowShortSecret`). Empty is never a secret.
    case 'HS256':
    case 'HS384':
    case 'HS512':
      return key.type === 'secret' && (key.symmetricKeySize ?? 0) >= (allowShortSecret ? 1 : HMAC_SECRET_BYTES[alg]);
    // One RSA key serves both paddings and every hash: the header names which, and the verifier's
    // `algorithms` decide which are accepted. Node's `rsa-pss` keys are refused (asymmetricKeyType
    // 'rsa-pss'): they restrict their own hash and salt, which a JWKS cannot even publish.
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return key.asymmetricKeyType === 'rsa' && (details?.modulusLength ?? 0) >= 2048;
    // Each ECDSA algorithm takes its own curve only: an ES256 token never verifies with a P-384 key.
    case 'ES256':
    case 'ES384':
    case 'ES512':
      return key.asymmetricKeyType === 'ec' && details?.namedCurve === CURVES[alg];
    case 'EdDSA':
      return key.asymmetricKeyType === 'ed25519';
    default:
      return false;
  }
}

/** What each algorithm needs, for the configuration error that names it. */
const RSA_KEY = 'an RSA key of at least 2048 bits';
const REQUIREMENTS: Record<JwsAlgorithm, string> = {
  HS256: 'a secret of at least 32 bytes (`openssl rand -base64 32`)',
  HS384: 'a secret of at least 48 bytes (`openssl rand -base64 48`)',
  HS512: 'a secret of at least 64 bytes (`openssl rand -base64 64`)',
  RS256: RSA_KEY,
  RS384: RSA_KEY,
  RS512: RSA_KEY,
  PS256: RSA_KEY,
  PS384: RSA_KEY,
  PS512: RSA_KEY,
  ES256: 'a P-256 key',
  ES384: 'a P-384 key',
  ES512: 'a P-521 key',
  EdDSA: 'an Ed25519 key',
};

/** HS256, HS384, HS512: signed and verified with the same secret, so no private key is involved. */
export const isHmac = (alg: JwsAlgorithm) => alg.startsWith('HS');

/** Throws a `TypeError` (configuration, not a token) unless `key` can serve `alg`. */
export function assertKeyFits(alg: JwsAlgorithm, key: KeyObject, owner: string, rules: KeyRules = {}): void {
  if (!keyFits(alg, key, rules)) {
    // A secret that is merely short names the opt-in: an app that must keep the secret it has (other
    // services verify with it) should not have to drop the package to do so.
    const short = isHmac(alg) && key.type === 'secret' && (key.symmetricKeySize ?? 0) > 0;
    throw new TypeError(
      `${owner}: the key is not a valid ${alg} key; ${alg} needs ${REQUIREMENTS[alg]}.` +
        (short
          ? ` To keep an existing shorter secret (${key.symmetricKeySize} bytes), set \`allowShortSecret: true\` ` +
            'next to the key; a short secret can be guessed offline from any token.'
          : ''),
    );
  }
}

/** Digests of the short secrets already warned about. */
const warnedShortSecrets = new Set<string>();

/**
 * Once per process and secret: a short secret is a choice the logs should show, not hide. The
 * signer and the verifier derived from it hold the same secret, so they warn once between them.
 */
export function warnShortSecret(alg: JwsAlgorithm, key: KeyObject, owner: string): void {
  if (!isHmac(alg) || key.type !== 'secret') {
    return;
  }
  const size = key.symmetricKeySize ?? 0;
  const minimum = HMAC_SECRET_BYTES[alg as keyof typeof HMAC_SECRET_BYTES];
  const digest = createHash('sha256').update(key.export()).digest('hex');
  if (size >= minimum || warnedShortSecrets.has(digest)) {
    return;
  }
  warnedShortSecrets.add(digest);
  new Logger(owner).warn(
    `The ${alg} secret is ${size} bytes, shorter than ${minimum} (\`allowShortSecret: true\`). Anyone holding a ` +
      `token can guess it offline and then sign their own. Replace it with \`openssl rand -base64 ${minimum}\` when you can.`,
  );
}

/** Throws a `TypeError` (configuration, not a token) unless `key` can sign `alg`. */
export function assertSigningKey(alg: JwsAlgorithm, key: KeyObject, owner: string, rules: KeyRules = {}): void {
  assertKeyFits(alg, key, owner, rules);
  if (!isHmac(alg) && key.type !== 'private') {
    throw new TypeError(`${owner}: ${alg} signing needs a private key.`);
  }
}

export function signJws(header: JwsHeader & { alg: JwsAlgorithm }, payload: object, key: KeyObject, rules: KeyRules = {}): string {
  assertSigningKey(header.alg, key, 'JwtSigner', rules);

  const input = `${encode(header)}.${encode(payload)}`;
  const data = Buffer.from(input);
  const { alg } = header;
  let signature: Buffer;
  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      signature = createHmac(hashOf(alg), key).update(data).digest();
      break;
    case 'RS256':
    case 'RS384':
    case 'RS512':
      signature = cryptoSign(hashOf(alg), data, key); // PKCS#1 v1.5 padding, Node's default for RSA
      break;
    case 'PS256':
    case 'PS384':
    case 'PS512':
      signature = cryptoSign(hashOf(alg), data, pss(key));
      break;
    case 'ES256':
    case 'ES384':
    case 'ES512':
      signature = cryptoSign(hashOf(alg), data, { key, dsaEncoding: 'ieee-p1363' });
      break;
    case 'EdDSA':
      signature = cryptoSign(null, data, key);
      break;
  }

  return `${input}.${signature.toString('base64url')}`;
}

export interface DecodedJws {
  header: JwsHeader;
  payload: JwtClaims;
  signingInput: Buffer;
  signature: Buffer;
}

/** Splits and decodes without verifying. */
export function decodeJws(token: string): DecodedJws {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => SEGMENT.test(p))) {
    throw new JwtError('malformed token');
  }

  const header = decodeJson(parts[0]) as JwsHeader;
  if (typeof header.alg !== 'string') {
    throw new JwtError('malformed token');
  }

  // One signature, one spelling: the unused low bits of the last character would otherwise give
  // several token strings for one token, and a list or a cache keyed by the string would miss them.
  const signature = Buffer.from(parts[2], 'base64url');
  if (signature.toString('base64url') !== parts[2]) {
    throw new JwtError('malformed token');
  }

  return {
    header,
    payload: decodeJson(parts[1]) as JwtClaims,
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
    signature,
  };
}

export function verifySignature(alg: JwsAlgorithm, key: KeyObject, decoded: DecodedJws, rules: KeyRules = {}): void {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  if (!keyFits(alg, publicKey, rules)) {
    throw new JwtError(`key is not a valid ${alg} key`);
  }

  const { signingInput, signature } = decoded;
  let valid: boolean;
  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512': {
      const expected = createHmac(hashOf(alg), publicKey).update(signingInput).digest();
      valid = signature.length === expected.length && timingSafeEqual(signature, expected);
      break;
    }
    case 'RS256':
    case 'RS384':
    case 'RS512':
      valid = cryptoVerify(hashOf(alg), signingInput, publicKey, signature);
      break;
    // Same key as RS, other padding: a PKCS#1 v1.5 signature presented as PS (or the reverse) fails here.
    case 'PS256':
    case 'PS384':
    case 'PS512':
      valid = cryptoVerify(hashOf(alg), signingInput, pss(publicKey), signature);
      break;
    case 'ES256':
    case 'ES384':
    case 'ES512':
      // JWS uses the raw r||s form (RFC 7518 §3.4), not DER.
      valid =
        signature.length === ECDSA_SIGNATURE_BYTES[alg] &&
        cryptoVerify(hashOf(alg), signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
      break;
    case 'EdDSA':
      valid = signature.length === 64 && cryptoVerify(null, signingInput, publicKey, signature);
      break;
    default:
      valid = false;
  }

  if (!valid) {
    throw new JwtError('invalid signature');
  }
}

/**
 * RSASSA-PSS options (RFC 7518 §3.5): MGF1 on the same hash (Node's default),
 * and a salt exactly as long as the hash. Verifying with this exact length,
 * not "any", refuses signatures made with another salt length.
 */
function pss(key: KeyObject) {
  return { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
}

export function validateClaims(claims: JwtClaims, rules: ClaimRules): void {
  // JWT times are seconds (RFC 7519 §2, NumericDate).
  const now = Math.floor((rules.now?.() ?? Date.now()) / 1000);
  const leeway = toMs(rules.clockTolerance ?? 0) / 1000;

  for (const name of rules.required ?? ['exp']) {
    if (claims[name] === undefined) {
      throw new JwtError(`missing ${name}`);
    }
  }

  for (const name of ['exp', 'nbf', 'iat'] as const) {
    if (claims[name] !== undefined && (typeof claims[name] !== 'number' || !Number.isFinite(claims[name]))) {
      throw new JwtError(`invalid ${name}`);
    }
  }

  // What `JwtClaims` promises `validate()`.
  for (const name of ['iss', 'sub', 'jti'] as const) {
    if (claims[name] !== undefined && typeof claims[name] !== 'string') {
      throw new JwtError(`invalid ${name}`);
    }
  }

  if (claims.exp !== undefined && now >= claims.exp + leeway) {
    throw new JwtError('token expired');
  }
  if (claims.nbf !== undefined && now < claims.nbf - leeway) {
    throw new JwtError('token not yet valid');
  }
  if (claims.iat !== undefined && claims.iat > now + leeway) {
    throw new JwtError('token issued in the future');
  }

  if (rules.maxAge !== undefined) {
    if (claims.iat === undefined) {
      throw new JwtError('missing iat');
    }
    if (now - claims.iat > toMs(rules.maxAge) / 1000 + leeway) {
      throw new JwtError('token too old');
    }
  }

  if (rules.issuer !== undefined) {
    const accepted = typeof rules.issuer === 'string' ? [rules.issuer] : rules.issuer;
    if (typeof claims.iss !== 'string' || !accepted.includes(claims.iss)) {
      throw new JwtError('unexpected issuer');
    }
  }

  if (rules.audience !== undefined && rules.audience !== false) {
    const accepted = ([] as string[]).concat(rules.audience);
    const given = ([] as unknown[]).concat(claims.aud ?? []);
    if (!given.some((aud) => typeof aud === 'string' && accepted.includes(aud))) {
      throw new JwtError('unexpected audience');
    }
  }
}

/**
 * Whether the bytes are a key or a certificate in DER, given as bytes or as
 * base64 text: never a secret (random bytes do not parse as DER), and what a
 * key management service's `GetPublicKey` or Keycloak's `public_key` gives.
 */
function isEncodedKey(key: string | Buffer): boolean {
  const candidates: Buffer[] = [];
  if (Buffer.isBuffer(key)) {
    candidates.push(key);
  }
  const compact = (typeof key === 'string' ? key : key.toString('latin1')).replace(/\s+/g, '');
  if (/^[A-Za-z0-9+/_-]{40,}={0,2}$/.test(compact)) {
    candidates.push(Buffer.from(compact, 'base64'));
  }

  const readers: ((der: Buffer) => unknown)[] = [
    (der) => createPublicKey({ key: der, format: 'der', type: 'spki' }),
    (der) => createPublicKey({ key: der, format: 'der', type: 'pkcs1' }),
    (der) => createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }),
    (der) => createPrivateKey({ key: der, format: 'der', type: 'pkcs1' }),
    (der) => createPrivateKey({ key: der, format: 'der', type: 'sec1' }),
    (der) => new X509Certificate(der),
  ];
  return candidates.some((der) =>
    readers.some((read) => {
      try {
        read(der);
        return true;
      } catch {
        return false;
      }
    }),
  );
}

/** A JSON Web Key (a JSON object with `kty`), as a JWKS or an environment variable holds one. */
function isJwk(text: string): boolean {
  if (!text.trimStart().startsWith('{')) {
    return false;
  }
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null && typeof (value as { kty?: unknown }).kty === 'string';
  } catch {
    return false;
  }
}

function encode(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function decodeJson(segment: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new JwtError('malformed token');
  }

  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new JwtError('malformed token');
  }
  return value as Record<string, unknown>;
}
