import { createPublicKey, verify, type JsonWebKey } from 'node:crypto';
import type { PasskeyAlgorithm } from '../interfaces/passkey-store.interface.js';

/** COSE algorithm ids (RFC 9053) of the credentials this package accepts. */
export const COSE_ALGORITHMS: Record<PasskeyAlgorithm, number> = {
  ES256: -7,
  RS256: -257,
  EdDSA: -8,
};

const MAX_DEPTH = 8;

/**
 * Decodes the first CBOR item of `bytes` (RFC 8949), and where it ends.
 * Only what attestation objects and COSE keys use: definite lengths,
 * integers up to 2^53, byte and text strings, arrays, maps, booleans and
 * null. Anything else throws.
 */
export function cborDecode(
  bytes: Buffer,
  start = 0,
  depth = 0,
): { value: unknown; end: number } {
  if (depth > MAX_DEPTH || start >= bytes.length) {
    throw new Error('CBOR: too deep or truncated');
  }
  const major = bytes[start] >> 5;
  const info = bytes[start] & 31;
  let offset = start + 1;
  let length: number;

  if (info < 24) {
    length = info;
  } else if (info <= 27) {
    const size = 1 << (info - 24);
    if (offset + size > bytes.length) {
      throw new Error('CBOR: truncated');
    }
    const big =
      size === 8
        ? bytes.readBigUInt64BE(offset)
        : BigInt(bytes.readUIntBE(offset, size));
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('CBOR: integer too large');
    }
    length = Number(big);
    offset += size;
  } else if (major === 7 && info >= 20 && info <= 22) {
    return {
      value: info === 20 ? false : info === 21 ? true : null,
      end: offset,
    };
  } else {
    throw new Error('CBOR: unsupported item');
  }

  switch (major) {
    case 0:
      return { value: length, end: offset };
    case 1:
      return { value: -1 - length, end: offset };
    case 2:
    case 3: {
      if (offset + length > bytes.length) {
        throw new Error('CBOR: truncated');
      }
      const raw = bytes.subarray(offset, offset + length);
      return {
        value: major === 2 ? raw : raw.toString('utf8'),
        end: offset + length,
      };
    }
    case 4:
    case 5: {
      // Each item takes at least a byte: a length past the input is a lie, not an allocation to make.
      if (length > bytes.length - offset) {
        throw new Error('CBOR: truncated');
      }
      const items: unknown[] = [];
      for (let i = 0; i < length * (major === 5 ? 2 : 1); i++) {
        const item = cborDecode(bytes, offset, depth + 1);
        items.push(item.value);
        offset = item.end;
      }
      if (major === 4) {
        return { value: items, end: offset };
      }
      const map = new Map<unknown, unknown>();
      for (let i = 0; i < items.length; i += 2) {
        map.set(items[i], items[i + 1]);
      }
      return { value: map, end: offset };
    }
    default:
      throw new Error('CBOR: unsupported item');
  }
}

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;

export interface AuthenticatorData {
  rpIdHash: Buffer;
  flags: number;
  counter: number;
  credential?: { id: Buffer; publicKey: Buffer };
}

/** Parses authenticator data (WebAuthn §6.1). `publicKey` is the COSE key, as CBOR. */
export function parseAuthenticatorData(data: Buffer): AuthenticatorData {
  if (data.length < 37) {
    throw new Error('authenticator data too short');
  }
  const parsed: AuthenticatorData = {
    rpIdHash: data.subarray(0, 32),
    flags: data[32],
    counter: data.readUInt32BE(33),
  };

  if (parsed.flags & FLAG_AT) {
    if (data.length < 55) {
      throw new Error('authenticator data too short');
    }
    const idLength = data.readUInt16BE(53);
    if (data.length < 55 + idLength) {
      throw new Error('authenticator data too short');
    }
    const keyStart = 55 + idLength;
    const { end } = cborDecode(data, keyStart);
    parsed.credential = {
      id: data.subarray(55, keyStart),
      publicKey: data.subarray(keyStart, end),
    };
  }
  return parsed;
}

/** A COSE key as SPKI DER, with its algorithm; throws for keys other than ES256, RS256 and EdDSA ones. */
export function coseToSpki(cose: Buffer): {
  algorithm: PasskeyAlgorithm;
  spki: Buffer;
} {
  const key = cborDecode(cose).value;
  if (!(key instanceof Map)) {
    throw new Error('COSE key is not a map');
  }
  const bytes = (label: number) => {
    const value = key.get(label);
    if (!Buffer.isBuffer(value)) {
      throw new Error('COSE key is missing a parameter');
    }
    return value.toString('base64url');
  };

  const alg = key.get(3);
  let algorithm: PasskeyAlgorithm;
  let jwk: JsonWebKey;
  if (alg === -7 && key.get(1) === 2 && key.get(-1) === 1) {
    algorithm = 'ES256';
    jwk = { kty: 'EC', crv: 'P-256', x: bytes(-2), y: bytes(-3) };
  } else if (alg === -257 && key.get(1) === 3) {
    algorithm = 'RS256';
    jwk = { kty: 'RSA', n: bytes(-1), e: bytes(-2) };
    // shortcut: a 2048-bit floor, raise it if NIST guidance moves on
    if (Buffer.from(jwk.n!, 'base64url').length < 256) {
      throw new Error('RSA key under 2048 bits');
    }
  } else if (alg === -8 && key.get(1) === 1 && key.get(-1) === 6) {
    algorithm = 'EdDSA';
    jwk = { kty: 'OKP', crv: 'Ed25519', x: bytes(-2) };
  } else {
    throw new Error('unsupported COSE key');
  }

  // Throws for a point not on the curve.
  return {
    algorithm,
    spki: createPublicKey({ key: jwk, format: 'jwk' }).export({
      type: 'spki',
      format: 'der',
    }),
  };
}

/**
 * Verifies an assertion signature over `authenticatorData || SHA-256(clientDataJSON)`.
 * ES256 signatures are DER (the default of `crypto.verify()` for EC keys), not the raw r||s of a JWS.
 */
export function verifyAssertion(
  algorithm: PasskeyAlgorithm,
  spki: Buffer,
  data: Buffer,
  signature: Buffer,
): boolean {
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  try {
    return verify(
      algorithm === 'EdDSA' ? null : 'sha256',
      data,
      key,
      signature,
    );
  } catch {
    return false;
  }
}
