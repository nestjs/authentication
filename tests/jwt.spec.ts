import { constants, createHmac, createSecretKey, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Logger } from '@nestjs/common';
import { JwksClient, JwtError, JwtSigner, JwtVerifier, type JwsAlgorithm } from '../lib/index.js';

const NOW = 1_800_000_000; // JWT times are in seconds
const nowMs = () => NOW * 1000; // clocks are epoch milliseconds
const SECRET = 'test-secret-that-is-at-least-32-bytes-long!';
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** Hand-rolled HS256 token, so malformed headers can be produced. */
function hs256(payload: object, header: object = { alg: 'HS256', typ: 'JWT' }, secret = SECRET) {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

/** An RS256 signature by any RSA key, which JwtSigner (2048 bits at least) would refuse to make. */
const sign256 = (input: string, key: KeyObject) => cryptoSign('sha256', Buffer.from(input), key).toString('base64url');

async function rejection(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(JwtError);
    return (error as Error).message;
  }

  throw new Error('expected a rejection');
}

// One key pair per curve: ES256 signs with P-256, ES384 with P-384, ES512 with P-521 (not "P-512").
const keys = {
  rsa: generateKeyPairSync('rsa', { modulusLength: 2048 }),
  ec: generateKeyPairSync('ec', { namedCurve: 'P-256' }),
  p384: generateKeyPairSync('ec', { namedCurve: 'P-384' }),
  p521: generateKeyPairSync('ec', { namedCurve: 'P-521' }),
  ed: generateKeyPairSync('ed25519'),
};

// HMAC secrets must be at least as long as the hash's output (RFC 7518 §3.2): 48 bytes for
// HS384, 64 for HS512. `SECRET` (43 bytes) is long enough for HS256 only.
const SECRET_48 = 'test-secret-for-hs384-that-is-at-least-48-bytes!';
const SECRET_64 = 'test-secret-for-hs512-that-must-be-at-least-sixty-four-bytes-long';

describe('allowShortSecret', () => {
  const SHORT = 'dev-secret'; // 10 bytes: what a `.env` often holds, and what other services may verify with
  const warn = () => vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  afterEach(() => vi.restoreAllMocks());

  it('names the option when a secret is merely short, and not for other bad keys', () => {
    expect(() => new JwtSigner({ key: SHORT })).toThrow(
      'JwtSigner: the key is not a valid HS256 key; HS256 needs a secret of at least 32 bytes (`openssl rand -base64 32`). ' +
        'To keep an existing shorter secret (10 bytes), set `allowShortSecret: true` next to the key; a short secret can be guessed offline from any token.',
    );
    expect(() => new JwtVerifier({ key: keys.rsa.publicKey, algorithms: ['HS256'], issuer: 'i', audience: 'a' })).toThrow(
      /^(?!.*allowShortSecret).*HS256 needs a secret/,
    );
  });

  it('signs plain HS256 with the secret as given, which the other side verifies with it', async () => {
    warn();
    const token = new JwtSigner({ key: SHORT, allowShortSecret: true, now: nowMs }).sign({ sub: 'u1' });
    const [header, payload, signature] = token.split('.');
    expect(JSON.parse(Buffer.from(header, 'base64url').toString())).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(signature).toBe(createHmac('sha256', SHORT).update(`${header}.${payload}`).digest('base64url'));

    const verifier = new JwtVerifier({ key: SHORT, allowShortSecret: true, now: nowMs });
    await expect(verifier.verify(token)).resolves.toMatchObject({ sub: 'u1' });
    expect(await rejection(verifier.verify(hs256({ sub: 'u1', exp: NOW + 10 }, undefined, 'dev-secreT')))).toBe('invalid signature');
  });

  it('relaxes the HS384 and HS512 minimums the same way, and never accepts an empty secret', () => {
    warn();
    expect(() => new JwtSigner({ key: SHORT, alg: 'HS512' })).toThrow(/64 bytes.*allowShortSecret/);
    expect(() => new JwtSigner({ key: SHORT, alg: 'HS384', allowShortSecret: true })).not.toThrow();
    expect(() => new JwtSigner({ key: SHORT, alg: 'HS512', allowShortSecret: true })).not.toThrow();
    expect(() => new JwtSigner({ key: createSecretKey(Buffer.alloc(0)), allowShortSecret: true })).toThrow(/^(?!.*allowShortSecret).*32 bytes/);
  });

  it('warns once per secret, the signer and its verifier together, and not for a long enough one', () => {
    const spy = warn();
    new JwtSigner({ key: SECRET, allowShortSecret: true });
    expect(spy).not.toHaveBeenCalled();

    const key = 'only-warned-once'; // 16 bytes, used by no other test: the warning is once per process
    new JwtSigner({ key, allowShortSecret: true });
    new JwtSigner({ key, allowShortSecret: true });
    new JwtVerifier({ key, allowShortSecret: true });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0][0]).toMatch(/The HS256 secret is 16 bytes, shorter than 32 .*guess it offline/);
  });
});

describe('JwtVerifier: HS256', () => {
  const verifier = (options = {}) => new JwtVerifier({ key: SECRET, now: nowMs, ...options });

  it('accepts a valid token', async () => {
    await expect(verifier().verify(hs256({ sub: 'u1', exp: NOW + 10 }))).resolves.toEqual({ sub: 'u1', exp: NOW + 10 });
  });

  it('refuses secrets shorter than 32 bytes, and HS256 with a JWKS', () => {
    expect(() => new JwtVerifier({ key: 'short' })).toThrow(/32 bytes/);
    expect(() => new JwtVerifier({ jwks: 'https://idp/jwks', algorithms: ['HS256'] })).toThrow(/HS256/);
  });

  it.each([
    ['none', { alg: 'none' }],
    ['HS512', { alg: 'HS512' }],
    ['RS256 on an HMAC verifier', { alg: 'RS256' }],
  ])('rejects alg %s', async (_, header) => {
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, header)))).toBe('unsupported algorithm');
  });

  it('rejects bad signatures, crit headers and malformed input', async () => {
    const good = hs256({ sub: 'u1', exp: NOW + 10 });
    const [h, , s] = good.split('.');

    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, undefined, 'z'.repeat(32))))).toBe('invalid signature');
    expect(await rejection(verifier().verify(`${h}.${b64({ sub: 'admin', exp: NOW + 10 })}.${s}`))).toBe('invalid signature');
    expect(await rejection(verifier().verify(good.slice(0, -3)))).toBe('invalid signature'); // truncated, still canonical
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, { alg: 'HS256', crit: ['x'] })))).toBe(
      'unsupported critical header',
    );

    for (const bad of ['a.b', 'a.b.c.d', `${h}.${b64({})}.`, '!!.e30.xx', `${b64([])}.e30.xx`]) {
      expect(await rejection(verifier().verify(bad))).toBe('malformed token');
    }
  });

  it('takes one spelling of a signature: the unused low bits of its last character must be zero', async () => {
    const good = hs256({ sub: 'u1', exp: NOW + 10 });
    const [h, p, s] = good.split('.');
    // 32 bytes are 43 characters; the last one carries 4 bits of the signature and 2 unused ones.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(s.at(-1)!);
    for (const unused of [1, 2, 3]) {
      const variant = `${h}.${p}.${s.slice(0, -1)}${alphabet[last | unused]}`;
      expect(await rejection(verifier().verify(variant))).toBe('malformed token');
    }
    await expect(verifier().verify(good)).resolves.toMatchObject({ sub: 'u1' });
  });

  it('refuses algorithm spellings, critical headers and base64 characters it does not know, and odd signature lengths', async () => {
    for (const alg of ['hs256', 'Hs256', 'HS256 ', 'none', 'HS512']) {
      expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, { alg })))).toBe('unsupported algorithm');
    }
    for (const crit of [[], null, 'b64']) {
      expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, { alg: 'HS256', crit })))).toBe('unsupported critical header');
    }

    const [h, p, s] = hs256({ sub: 'u1', exp: NOW + 10 }).split('.');
    for (const bad of [`${h}=.${p}.${s}`, `${h}.${p}+.${s}`, `${h}.${p}.${s.replace('A', '/')}/`, `${h}.${p} .${s}`, `${h}.${p}.${s}=`]) {
      expect(await rejection(verifier().verify(bad))).toBe('malformed token');
    }

    // A signature of any other length is refused as invalid (a 401), never an error (a 500).
    const rsa = new JwtVerifier({ key: keys.rsa.publicKey, now: nowMs, issuer: 'i', audience: false });
    const ed = new JwtVerifier({ key: keys.ed.publicKey, now: nowMs, issuer: 'i', audience: false });
    const input = (alg: string) => `${b64({ alg })}.${b64({ iss: 'i', exp: NOW + 10 })}`;
    for (const bytes of [1, 255, 257, 512]) {
      expect(await rejection(rsa.verify(`${input('RS256')}.${Buffer.alloc(bytes, 7).toString('base64url')}`))).toBe('invalid signature');
    }
    for (const bytes of [63, 65]) {
      expect(await rejection(ed.verify(`${input('EdDSA')}.${Buffer.alloc(bytes, 7).toString('base64url')}`))).toBe('invalid signature');
    }
  });

  it('matches `iss` and `aud` exactly, never by prefix, case or trailing slash', async () => {
    const pinned = verifier({ issuer: 'https://idp.test', audience: 'my-api' });
    for (const iss of ['https://idp.test/', 'https://idp.test.evil', 'HTTPS://IDP.TEST', 'https://idp']) {
      expect(await rejection(pinned.verify(hs256({ iss, aud: 'my-api', exp: NOW + 10 })))).toBe('unexpected issuer');
    }
    for (const aud of ['my-api ', 'my-apix', 'MY-API', ['my', 'api'], 'my']) {
      expect(await rejection(pinned.verify(hs256({ iss: 'https://idp.test', aud, exp: NOW + 10 })))).toBe('unexpected audience');
    }
    await expect(pinned.verify(hs256({ iss: 'https://idp.test', aud: ['other', 'my-api'], exp: NOW + 10 }))).resolves.toBeTruthy();
  });

  it('checks time claims with leeway, and requires exp by default', async () => {
    expect(await rejection(verifier().verify(hs256({ exp: NOW })))).toBe('token expired');
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10, nbf: NOW + 1 })))).toBe('token not yet valid');
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10, iat: NOW + 100 })))).toBe('token issued in the future');
    expect(await rejection(verifier().verify(hs256({ exp: String(NOW + 10) })))).toBe('invalid exp');
    expect(await rejection(verifier().verify(hs256({ sub: 'u1' })))).toBe('missing exp');

    await expect(verifier({ clockTolerance: '5s' }).verify(hs256({ exp: NOW - 2, nbf: NOW + 2 }))).resolves.toBeTruthy();
    expect(await rejection(verifier({ maxAge: '1m' }).verify(hs256({ exp: NOW + 10, iat: NOW - 61 })))).toBe('token too old');
  });

  it('checks iss, aud and typ', async () => {
    const v = verifier({ issuer: 'https://idp', audience: ['api', 'admin'], type: 'at+jwt' });
    const header = { alg: 'HS256', typ: 'at+jwt' };

    await expect(v.verify(hs256({ iss: 'https://idp', aud: ['x', 'admin'], exp: NOW + 1 }, header))).resolves.toBeTruthy();
    expect(await rejection(v.verify(hs256({ iss: 'https://evil', aud: 'api', exp: NOW + 1 }, header)))).toBe('unexpected issuer');
    expect(await rejection(v.verify(hs256({ iss: 'https://idp', aud: 'x', exp: NOW + 1 }, header)))).toBe('unexpected audience');
    expect(await rejection(v.verify(hs256({ iss: 'https://idp', aud: 'api', exp: NOW + 1 })))).toBe('unexpected token type');
  });
});

describe('JwtSigner + JwtVerifier: asymmetric', () => {
  // A public key verifies another party's tokens: pinned to their issuer, here with any audience.
  const foreign = { issuer: 'i', audience: false } as const;
  const cases: [JwsAlgorithm, { privateKey: KeyObject; publicKey: KeyObject }][] = [
    ['RS256', keys.rsa],
    ['ES256', keys.ec],
    ['EdDSA', keys.ed],
  ];

  it.each(cases)('%s round-trips and derives the algorithm from the key', async (alg, pair) => {
    const token = new JwtSigner({ key: pair.privateKey, alg, now: nowMs, issuer: 'i' }).sign({ sub: 'u1' });
    const claims = await new JwtVerifier({ key: pair.publicKey, now: nowMs, ...foreign }).verify(token);
    expect(claims).toMatchObject({ sub: 'u1', iat: NOW, exp: NOW + 900, iss: 'i' });
    expect(claims.jti).toEqual(expect.any(String));
  });

  it('binds algorithms to key types (no RSA/HMAC confusion, no curve confusion)', async () => {
    // Classic attack: HS256 token whose "secret" is the RSA public key PEM.
    const pem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' });
    const forged = hs256({ sub: 'admin', exp: NOW + 10 }, { alg: 'HS256' }, pem as string);
    expect(await rejection(new JwtVerifier({ key: keys.rsa.publicKey, now: nowMs, ...foreign }).verify(forged))).toBe(
      'unsupported algorithm',
    );

    // An algorithm the key cannot serve fails when the verifier is created, not at the first request.
    expect(() => new JwtVerifier({ key: keys.rsa.publicKey, algorithms: ['HS256'] })).toThrow(
      /JwtVerifier: the key is not a valid HS256 key/,
    );

    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    expect(() => new JwtSigner({ key: p384.privateKey, alg: 'ES256' })).toThrow(/not a valid ES256 key/);
    expect(() => new JwtSigner({ key: keys.ec.publicKey, alg: 'ES256' })).toThrow(/private key/);
    expect(() => new JwtSigner({ key: generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey, alg: 'RS256' })).toThrow();
    expect(() => new JwtSigner({ key: generateKeyPairSync('ed448').privateKey, alg: 'EdDSA' })).toThrow();
  });

  it('reads PEM text as the key it is, never as an HS256 secret', async () => {
    // jsonwebtoken users pass keys as PEM strings. Read as an HMAC secret, a
    // public key would let anyone who has it (everyone) sign tokens.
    const publicPem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const forged = hs256({ sub: 'admin', exp: NOW + 10 }, { alg: 'HS256' }, publicPem);
    for (const key of [publicPem, Buffer.from(publicPem)]) {
      expect(await rejection(new JwtVerifier({ key, now: nowMs, ...foreign }).verify(forged))).toBe('unsupported algorithm');
    }
    expect(() => new JwtVerifier({ key: publicPem, algorithms: ['HS256'] })).toThrow(/not a valid HS256 key/);

    // PEM keys work as keys: PKCS#1 and SEC1 private keys sign, SPKI keys verify.
    const header = (token: string) => JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
    const rsaPem = keys.rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
    const token = new JwtSigner({ key: rsaPem, now: nowMs, issuer: 'i' }).sign({ sub: 'u1' });
    expect(header(token).alg).toBe('RS256');
    await expect(new JwtVerifier({ key: publicPem, now: nowMs, ...foreign }).verify(token)).resolves.toMatchObject({ sub: 'u1' });

    const ecPem = keys.ec.privateKey.export({ type: 'sec1', format: 'pem' }) as string;
    expect(header(new JwtSigner({ key: ecPem }).sign({})).alg).toBe('ES256');
    expect(() => new JwtSigner({ key: publicPem })).toThrow(/private key/);
  });

  it('pins a public key to its issuer and the app, as a JWKS: an identity provider signs every client’s tokens', async () => {
    const token = (audience: string) =>
      new JwtSigner({ key: keys.rsa.privateKey, issuer: 'https://idp.test', audience, now: nowMs }).sign({ sub: 'u1' });

    expect(() => new JwtVerifier({ key: keys.rsa.publicKey })).toThrow('JwtVerifier: a public `key` verifier needs `issuer` and `audience`.');
    const publicPem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    expect(() => new JwtVerifier({ key: publicPem, issuer: 'https://idp.test' })).toThrow(/needs `issuer` and `audience`/);

    const pinned = new JwtVerifier({ key: keys.rsa.publicKey, issuer: 'https://idp.test', audience: 'my-api', now: nowMs });
    await expect(pinned.verify(token('my-api'))).resolves.toMatchObject({ sub: 'u1' });
    expect(await rejection(pinned.verify(token('self-registration')))).toBe('unexpected audience'); // another client of the realm

    // The app's own keys, a secret or a private key, need neither.
    expect(() => new JwtVerifier({ key: keys.rsa.privateKey })).not.toThrow();
    expect(() => new JwtVerifier({ key: SECRET })).not.toThrow();
  });

  it('refuses a key given as DER, or base64 of it, which would otherwise be an HS256 secret anyone can derive', () => {
    const spki = keys.rsa.publicKey.export({ type: 'spki', format: 'der' });
    const base64 = spki.toString('base64'); // Keycloak's realm `public_key`
    const certificateless = keys.ec.publicKey.export({ type: 'spki', format: 'der' });

    for (const key of [spki, base64, `${base64.slice(0, 64)}\n${base64.slice(64)}`, certificateless, keys.ed.privateKey.export({ type: 'pkcs8', format: 'der' })]) {
      expect(() => new JwtVerifier({ key })).toThrow(/^The key is DER .* which would be read as an HS256 secret/);
    }
    // Random secrets, as `openssl rand -base64 32` and `-hex 32` make them, are secrets.
    for (const secret of ['q2wP0v3m4Xx1Yk8b7T6s5R4q3P2o1N0m9L8k7J6i5H4=', 'ab'.repeat(32)]) {
      expect(() => new JwtVerifier({ key: secret })).not.toThrow();
    }
  });

  it('reads the private key of a PEM bundle, whatever block comes first', () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const params = '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n';
    const bundle = params + (pair.privateKey.export({ type: 'sec1', format: 'pem' }) as string);

    const token = new JwtSigner({ key: bundle, now: nowMs, issuer: 'i' }).sign({ sub: 'u1' });
    return expect(new JwtVerifier({ key: pair.publicKey, now: nowMs, ...foreign }).verify(token)).resolves.toMatchObject({ sub: 'u1' });
  });

  it('rejects DER-encoded ES256 signatures (JWS needs raw r||s)', async () => {
    const token = new JwtSigner({ key: keys.ec.privateKey, alg: 'ES256', now: nowMs }).sign({});
    const [h, p] = token.split('.');
    const { sign } = await import('node:crypto');
    const der = sign('sha256', Buffer.from(`${h}.${p}`), keys.ec.privateKey).toString('base64url');

    expect(await rejection(new JwtVerifier({ key: keys.ec.publicKey, now: nowMs, ...foreign }).verify(`${h}.${p}.${der}`))).toBe(
      'invalid signature',
    );
  });

  it('accepts a KeyObject secret for HS256', async () => {
    const key = createSecretKey(Buffer.from(SECRET));
    const token = new JwtSigner({ key, alg: 'HS256', now: nowMs }).sign({ sub: 'u1' });
    await expect(new JwtVerifier({ key: SECRET, now: nowMs }).verify(token)).resolves.toMatchObject({ sub: 'u1' });
  });

  it('takes the algorithm from the key, and lifetimes as durations', async () => {
    const header = (token: string) => JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
    const ec = new JwtSigner({ key: keys.ec.privateKey, ttl: '1h', now: nowMs, issuer: 'i' });
    expect(header(ec.sign({}))).toEqual({ alg: 'ES256', typ: 'JWT' });
    expect(header(new JwtSigner({ key: SECRET }).sign({})).alg).toBe('HS256');

    const verifier = new JwtVerifier({ key: keys.ec.publicKey, now: nowMs, ...foreign });
    await expect(verifier.verify(ec.sign({}))).resolves.toMatchObject({ iat: NOW, exp: NOW + 3600 });
    await expect(verifier.verify(ec.sign({}, { ttl: '2m' }))).resolves.toMatchObject({ exp: NOW + 120 });

    expect(() => new JwtSigner({ key: SECRET, ttl: '15 minutes' as never })).toThrow(/Invalid duration/);
    expect(() => new JwtVerifier({ key: SECRET, clockTolerance: -5 })).toThrow(/Invalid duration/);
  });
});

/**
 * The algorithms beyond the defaults. None of them is accepted unless a verifier lists it in
 * `algorithms` (or, for ES384/ES512, is given a key of that curve), so they are opt-in, and
 * each is bound to exactly one kind of key: the defence against key-confusion forgeries.
 */
describe('JwtSigner + JwtVerifier: RS384/512, PS256/384/512, ES384/512, HS384/512', () => {
  // A public key verifies another party's tokens: pinned to their issuer, here with any audience.
  const foreign = { issuer: 'i', audience: false } as const;
  const header = (token: string) => JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  // The `header.payload` part of a token, for signing by hand: how the forged tokens below are made.
  const input = (alg: string) => `${b64({ alg })}.${b64({ iss: 'i', exp: NOW + 10 })}`;

  it.each<[JwsAlgorithm, { privateKey: KeyObject; publicKey: KeyObject }]>([
    ['RS384', keys.rsa],
    ['RS512', keys.rsa],
    ['PS256', keys.rsa],
    ['PS384', keys.rsa],
    ['PS512', keys.rsa],
    ['ES384', keys.p384],
    ['ES512', keys.p521],
  ])('%s round-trips when the verifier accepts it', async (alg, pair) => {
    // The header names the algorithm the signer was given, and a verifier that lists it accepts the token.
    const token = new JwtSigner({ key: pair.privateKey, alg, now: nowMs, issuer: 'i' }).sign({ sub: 'u1' });
    expect(header(token).alg).toBe(alg);
    const verifier = new JwtVerifier({ key: pair.publicKey, algorithms: [alg], now: nowMs, ...foreign });
    await expect(verifier.verify(token)).resolves.toMatchObject({ sub: 'u1', iss: 'i' });
  });

  it.each<[JwsAlgorithm, string]>([
    ['HS384', SECRET_48],
    ['HS512', SECRET_64],
  ])('%s round-trips with a secret as long as its hash', async (alg, secret) => {
    const token = new JwtSigner({ key: secret, alg, now: nowMs }).sign({ sub: 'u1' });
    expect(header(token).alg).toBe(alg);
    await expect(new JwtVerifier({ key: secret, algorithms: [alg], now: nowMs }).verify(token)).resolves.toMatchObject({ sub: 'u1' });
  });

  it('takes ES384 and ES512 from the curve, but never PS or a longer hash from an RSA key', async () => {
    // An EC key fits exactly one algorithm, so it can be implied. An RSA key fits six (RS and PS,
    // three hashes each) and a secret three: they keep their old default, and the rest are opted into.
    expect(header(new JwtSigner({ key: keys.p384.privateKey }).sign({})).alg).toBe('ES384');
    expect(header(new JwtSigner({ key: keys.p521.privateKey }).sign({})).alg).toBe('ES512');
    expect(header(new JwtSigner({ key: keys.rsa.privateKey }).sign({})).alg).toBe('RS256');
    expect(header(new JwtSigner({ key: SECRET_64 }).sign({})).alg).toBe('HS256');

    const p384 = new JwtVerifier({ key: keys.p384.publicKey, now: nowMs, ...foreign });
    expect(p384.algorithms).toEqual(['ES384']);
    await expect(p384.verify(new JwtSigner({ key: keys.p384.privateKey, now: nowMs, issuer: 'i' }).sign({}))).resolves.toBeTruthy();

    // An RSA key's verifier accepts RS256 only until PS256 or a longer hash is opted into.
    const ps256 = new JwtSigner({ key: keys.rsa.privateKey, alg: 'PS256', now: nowMs, issuer: 'i' }).sign({});
    const rs512 = new JwtSigner({ key: keys.rsa.privateKey, alg: 'RS512', now: nowMs, issuer: 'i' }).sign({});
    const rsa = new JwtVerifier({ key: keys.rsa.publicKey, now: nowMs, ...foreign });
    expect(await rejection(rsa.verify(ps256))).toBe('unsupported algorithm');
    expect(await rejection(rsa.verify(rs512))).toBe('unsupported algorithm');
    // Likewise a secret's verifier and HS512.
    const hs512 = new JwtSigner({ key: SECRET_64, alg: 'HS512', now: nowMs }).sign({});
    expect(await rejection(new JwtVerifier({ key: SECRET_64, now: nowMs }).verify(hs512))).toBe('unsupported algorithm');
  });

  it('binds each algorithm to its key: no curve, size, family or RSA-PSS key confusion', () => {
    // Every misconfiguration fails when the signer or verifier is created (a `TypeError`), never at
    // the first request. Each curve serves its own algorithm only.
    expect(() => new JwtSigner({ key: keys.ec.privateKey, alg: 'ES384' })).toThrow(/not a valid ES384 key; ES384 needs a P-384 key/);
    expect(() => new JwtSigner({ key: keys.p384.privateKey, alg: 'ES512' })).toThrow(/not a valid ES512 key; ES512 needs a P-521 key/);
    expect(() => new JwtSigner({ key: keys.p521.privateKey, alg: 'ES256' })).toThrow(/not a valid ES256 key/);
    expect(() => new JwtVerifier({ key: keys.p384.publicKey, algorithms: ['ES256'], ...foreign })).toThrow(/not a valid ES256 key/);
    // A curve no algorithm takes is named, not reported as if EC keys were unsupported.
    const k256 = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    expect(() => new JwtSigner({ key: k256.privateKey })).toThrow('JwtSigner: EC keys on secp256k1 are not supported (use P-256, P-384 or P-521).');
    expect(() => new JwtVerifier({ key: k256.publicKey, ...foreign })).toThrow('JwtVerifier: EC keys on secp256k1 are not supported');

    // A secret at least as long as the hash's output.
    expect(() => new JwtSigner({ key: SECRET, alg: 'HS384' })).toThrow(/HS384 needs a secret of at least 48 bytes/);
    expect(() => new JwtSigner({ key: SECRET_48, alg: 'HS512' })).toThrow(/HS512 needs a secret of at least 64 bytes/);
    expect(() => new JwtVerifier({ key: SECRET, algorithms: ['HS512'] })).toThrow(/not a valid HS512 key/);

    // An RSA key never serves an HMAC algorithm, nor a secret an RSA one, whatever else is accepted:
    // HMAC with a public key as the secret is the classic forgery (anyone has the public key).
    expect(() => new JwtVerifier({ key: keys.rsa.publicKey, algorithms: ['PS256', 'HS512'], ...foreign })).toThrow(/not a valid HS512 key/);
    expect(() => new JwtSigner({ key: SECRET_64, alg: 'PS256' })).toThrow(/not a valid PS256 key/);
    expect(() => new JwtSigner({ key: keys.rsa.publicKey, alg: 'PS384' })).toThrow(/private key/);
    expect(() => new JwtSigner({ key: generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey, alg: 'PS256' })).toThrow(
      /at least 2048 bits/,
    );

    // Node's `rsa-pss` keys carry their own hash and salt restrictions: refused, not guessed at.
    const restricted = generateKeyPairSync('rsa-pss', { modulusLength: 2048 });
    expect(() => new JwtSigner({ key: restricted.privateKey })).toThrow(/rsa-pss keys are not supported/);
    expect(() => new JwtSigner({ key: restricted.privateKey, alg: 'PS256' })).toThrow(/not a valid PS256 key/);
  });

  it('rejects PKCS#1 v1.5 and PSS signatures presented as each other, and other hashes or salt lengths', async () => {
    // RS and PS share one RSA key but pad differently, so a verifier that accepts both must still check
    // the padding the header names. The tokens are signed by hand, as JwtSigner only signs correctly.
    const verifier = new JwtVerifier({ key: keys.rsa.publicKey, algorithms: ['RS256', 'PS256', 'PS384'], now: nowMs, ...foreign });
    const token = (alg: string, sign: (data: Buffer) => Buffer) => `${input(alg)}.${sign(Buffer.from(input(alg))).toString('base64url')}`;
    const pss = (saltLength: number) => ({ key: keys.rsa.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength });

    // The control: a correct PS256 signature, SHA-256 with a 32-byte salt, verifies.
    await expect(verifier.verify(token('PS256', (data) => cryptoSign('sha256', data, pss(32))))).resolves.toBeTruthy();
    const forged = [
      token('RS256', (data) => cryptoSign('sha256', data, pss(32))), // PSS presented as PKCS#1 v1.5
      token('PS256', (data) => cryptoSign('sha256', data, keys.rsa.privateKey)), // and the reverse
      token('PS384', (data) => cryptoSign('sha256', data, pss(32))), // another hash than its alg names
      token('PS256', (data) => cryptoSign('sha256', data, pss(20))), // a salt shorter than the hash (RFC 7518 §3.5)
      token('PS256', (data) => cryptoSign('sha256', data, pss(64))), // or longer
    ];
    for (const bad of forged) {
      expect(await rejection(verifier.verify(bad))).toBe('invalid signature');
    }
  });

  it('takes raw r||s ECDSA signatures of the curve’s exact length only', async () => {
    // JWS signatures are r and s side by side, each the curve's size (RFC 7518 §3.4). Any other length
    // is refused as an invalid signature (a 401), never passed on to the crypto library to fail with a 500.
    const cases: [JwsAlgorithm, KeyObject, string, number[]][] = [
      ['ES384', keys.p384.publicKey, 'sha384', [64, 95, 97, 104]],
      // P-521 coordinates are 66 bytes: 132, not the 128 the name suggests.
      ['ES512', keys.p521.publicKey, 'sha512', [128, 131, 133, 139]],
    ];
    for (const [alg, publicKey, hash, lengths] of cases) {
      const verifier = new JwtVerifier({ key: publicKey, algorithms: [alg], now: nowMs, ...foreign });
      for (const bytes of lengths) {
        expect(await rejection(verifier.verify(`${input(alg)}.${Buffer.alloc(bytes, 7).toString('base64url')}`))).toBe('invalid signature');
      }

      // A DER signature by the right key is refused too: JWS needs the raw form.
      const privateKey = alg === 'ES384' ? keys.p384.privateKey : keys.p521.privateKey;
      const der = cryptoSign(hash, Buffer.from(input(alg)), privateKey).toString('base64url');
      expect(await rejection(verifier.verify(`${input(alg)}.${der}`))).toBe('invalid signature');
    }
  });
});

describe('JwksClient', () => {
  let server: Server;
  let uri: string;
  let published: object[];
  let status = 200;
  let requests = 0;

  const jwk = (key: KeyObject, kid: string, extra: object = {}) => ({ ...key.export({ format: 'jwk' }), kid, ...extra });

  beforeAll(async () => {
    server = createServer((_, res) => {
      requests++;
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ keys: published }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    uri = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks`;
  });
  afterAll(() => new Promise((resolve) => server.close(resolve)));
  beforeEach(() => {
    requests = 0;
    status = 200;
    published = [jwk(keys.rsa.publicKey, 'rsa-1', { alg: 'RS256', use: 'sig' }), jwk(keys.ec.publicKey, 'ec-1')];
  });

  // The identity provider, and the API the tokens are for.
  const idp = { issuer: 'https://idp.test', audience: 'my-api' };
  const sign = (alg: JwsAlgorithm, key: KeyObject, kid?: string, audience = idp.audience) =>
    new JwtSigner({ key, alg, kid, now: nowMs, issuer: idp.issuer, audience }).sign({ sub: 'u1' });

  it('verifies by kid, caches the set, and ignores encryption keys', async () => {
    published.push(jwk(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey, 'enc', { use: 'enc' }));
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });

    await verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'));
    await verifier.verify(sign('ES256', keys.ec.privateKey, 'ec-1'));
    expect(requests).toBe(1);

    expect(await rejection(verifier.verify(sign('RS256', keys.rsa.privateKey, 'enc')))).toBe('no matching key');
  });

  it('refetches on an unknown kid (rotation), at most once per cooldown', async () => {
    let clock = 0;
    const client = new JwksClient(uri, { cooldown: 30_000, now: () => clock });
    const verifier = new JwtVerifier({ jwks: client, ...idp, now: nowMs });
    await verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'));

    const rotated = generateKeyPairSync('rsa', { modulusLength: 2048 });
    published = [jwk(rotated.publicKey, 'rsa-2')];
    clock = 1_000; // within cooldown: the unknown kid does not trigger a fetch
    expect(await rejection(verifier.verify(sign('RS256', rotated.privateKey, 'rsa-2')))).toBe('no matching key');
    expect(requests).toBe(1);

    clock = 31_000;
    await expect(verifier.verify(sign('RS256', rotated.privateKey, 'rsa-2'))).resolves.toBeTruthy();
    expect(requests).toBe(2);

    // Old key is gone after rotation.
    clock = 62_000;
    expect(await rejection(verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1')))).toBe('no matching key');
  });

  it('shares one request between concurrent refreshes', async () => {
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    const token = sign('RS256', keys.rsa.privateKey, 'rsa-1');
    await Promise.all(Array.from({ length: 10 }, () => verifier.verify(token)));
    expect(requests).toBe(1);
  });

  it('keeps serving cached keys when a refresh fails', async () => {
    let clock = 0;
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri, { cacheTtl: 1_000, now: () => clock }), ...idp, now: nowMs });
    const token = sign('RS256', keys.rsa.privateKey, 'rsa-1');
    await verifier.verify(token);

    status = 500;
    clock = 5_000;
    await expect(verifier.verify(token)).resolves.toBeTruthy();
  });

  it('refuses a JWK whose alg disagrees with the token, and kid-less tokens against ambiguous sets', async () => {
    published = [jwk(keys.rsa.publicKey, 'rsa-1', { alg: 'PS256' })];
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    expect(await rejection(verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1')))).toBe('no matching key');

    published = [jwk(keys.rsa.publicKey, 'a'), jwk(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey, 'b')];
    const ambiguous = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    expect(await rejection(ambiguous.verify(sign('RS256', keys.rsa.privateKey)))).toBe('no matching key');
  });

  it('verifies a kid-less token with the one key of the set that fits its algorithm', async () => {
    // The default set holds an RSA and an EC key: only one of them can verify RS256.
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    await expect(verifier.verify(sign('RS256', keys.rsa.privateKey))).resolves.toMatchObject({ sub: 'u1' });
    await expect(verifier.verify(sign('ES256', keys.ec.privateKey))).resolves.toMatchObject({ sub: 'u1' });
  });

  it('refuses a token signed by an RSA key of the set that is under 2048 bits', async () => {
    const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
    published = [jwk(weak.publicKey, 'weak', { alg: 'RS256', use: 'sig' })];
    // JwtSigner refuses to sign with such a key: sign by hand, as a careless issuer would.
    const input = `${b64({ alg: 'RS256', kid: 'weak' })}.${b64({ sub: 'u1', iss: idp.issuer, aud: idp.audience, exp: NOW + 60 })}`;
    const token = `${input}.${sign256(input, weak.privateKey)}`;

    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    expect(await rejection(verifier.verify(token))).toBe('key is not a valid RS256 key');
  });

  it('ignores keys it cannot verify with: symmetric, other curves, `key_ops` without verify, unreadable', async () => {
    published = [
      { kty: 'oct', k: Buffer.from(SECRET).toString('base64url'), kid: 'oct' },
      jwk(generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).publicKey, 'k256'),
      jwk(keys.rsa.publicKey, 'ops', { key_ops: ['encrypt'] }),
      { kty: 'RSA', kid: 'broken' },
    ];
    const client = new JwksClient(uri);
    const verifier = new JwtVerifier({ jwks: client, ...idp, now: nowMs });

    for (const kid of ['k256', 'ops', 'broken']) {
      expect(await rejection(verifier.verify(sign('RS256', keys.rsa.privateKey, kid)))).toBe('no matching key');
    }
    // A shared secret published in the set is no key at all, and HS256 is no JWKS algorithm.
    expect(await rejection(client.getKey({ alg: 'RS256', kid: 'oct' }))).toBe('no matching key');
    expect(await rejection(client.getKey({ alg: 'HS256', kid: 'oct' }))).toBe('unsupported algorithm');
    expect(requests).toBe(1);
  });

  it('skips entries it cannot read, and still loads the rest of the set', async () => {
    const opsNull = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const opsText = generateKeyPairSync('rsa', { modulusLength: 2048 });
    published = [
      null,
      'a string',
      jwk(opsNull.publicKey, 'ops-null', { key_ops: null }),
      jwk(opsText.publicKey, 'ops-text', { key_ops: 'verify' }), // a string, not a list: `includes` would find it
      jwk(keys.rsa.publicKey, 'rsa-1', { kid: 'rsa-1', alg: 'RS256' }),
    ] as object[];
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });

    await expect(verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'))).resolves.toMatchObject({ sub: 'u1' });
    expect(await rejection(verifier.verify(sign('RS256', opsNull.privateKey, 'ops-null')))).toBe('no matching key');
    expect(await rejection(verifier.verify(sign('RS256', opsText.privateKey, 'ops-text')))).toBe('no matching key');
  });

  it('fetches a key set over https only, but on loopback', () => {
    for (const bad of ['http://idp.example.com/jwks', 'ftp://idp.example.com/jwks', 'not a url', '']) {
      expect(() => new JwksClient(bad)).toThrow(/^JwksClient: the key set must be an https URL \(http only on loopback\)/);
    }
    expect(() => new JwtVerifier({ jwks: 'http://idp.example.com/jwks', ...idp })).toThrow(/must be an https URL/);
    for (const good of ['https://idp.example.com/jwks', 'http://localhost:8080/jwks', 'http://127.0.0.1/jwks', 'http://[::1]/jwks']) {
      expect(() => new JwksClient(good)).not.toThrow();
    }
  });

  it('refuses a key set that redirects, and gives up on one that does not answer', async () => {
    let redirects = 0;
    const redirecting = createServer((_, res) => {
      redirects++;
      res.writeHead(302, { location: uri }).end();
    });
    const stalled = createServer(() => undefined); // never answers
    await Promise.all([redirecting, stalled].map((s) => new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve))));
    const at = (s: Server) => `http://127.0.0.1:${(s.address() as AddressInfo).port}/jwks`;
    try {
      const followed = new JwtVerifier({ jwks: new JwksClient(at(redirecting)), ...idp, now: nowMs });
      await expect(followed.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'))).rejects.toThrow(/is unavailable/);
      expect([redirects, requests]).toEqual([1, 0]); // the redirect was not followed

      const started = Date.now();
      const waiting = new JwtVerifier({ jwks: new JwksClient(at(stalled), { timeout: 200 }), ...idp, now: nowMs });
      await expect(waiting.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'))).rejects.toThrow(/is unavailable/);
      expect(Date.now() - started).toBeLessThan(2_000);
    } finally {
      stalled.closeAllConnections();
      await Promise.all([redirecting, stalled].map((s) => new Promise((resolve) => s.close(resolve))));
    }
  });

  it('reports a key set without a `keys` array as an outage, not as a bad token', async () => {
    published = undefined as unknown as object[]; // the endpoint answers `{}`
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });

    const error = await verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1')).catch((e: Error) => e);
    expect(error).not.toBeInstanceOf(JwtError);
    expect((error as Error).message).toBe(`JWKS ${uri} is unavailable: it has no keys array`);
  });

  it('needs an issuer and an audience: an identity provider signs tokens for all of its clients', async () => {
    expect(() => new JwtVerifier({ jwks: uri })).toThrow(
      'JwtVerifier: a `jwks` verifier needs `issuer` and `audience`.',
    );
    expect(() => new JwtVerifier({ jwks: uri, issuer: idp.issuer })).toThrow(/needs `issuer` and `audience`/);

    // A token the same provider issued to another application.
    const other = sign('RS256', keys.rsa.privateKey, 'rsa-1', 'another-app');
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    expect(await rejection(verifier.verify(other))).toBe('unexpected audience');

    // Tokens that carry no audience (AWS Cognito access tokens) take an explicit opt-out.
    const anyAudience = new JwtVerifier({ jwks: new JwksClient(uri), issuer: idp.issuer, audience: false, now: nowMs });
    await expect(anyAudience.verify(other)).resolves.toMatchObject({ aud: 'another-app' });
  });

  it('reports an unreachable key set as an outage, not as a bad token', async () => {
    status = 503;
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });

    const error = await verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1')).catch((e: Error) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(JwtError); // JwtBearerProvider answers JwtErrors with a 401
    expect((error as Error).message).toBe(`JWKS ${uri} is unavailable: it answered 503`);
  });

  it('retries a key set that failed to load at most once per cooldown', async () => {
    let clock = 0;
    status = 503;
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri, { cooldown: 30_000, now: () => clock }), ...idp, now: nowMs });
    const token = sign('RS256', keys.rsa.privateKey, 'rsa-1');

    await expect(verifier.verify(token)).rejects.toThrow(/is unavailable/);
    clock = 10_000;
    await expect(verifier.verify(token)).rejects.toThrow(/is unavailable/);
    expect(requests).toBe(1); // the provider is down: no request per incoming token

    status = 200;
    clock = 31_000;
    await expect(verifier.verify(token)).resolves.toMatchObject({ sub: 'u1' });
    expect(requests).toBe(2);
  });

  it('verifies EdDSA only when enabled', async () => {
    published = [jwk(keys.ed.publicKey, 'ed-1')];
    const token = sign('EdDSA', keys.ed.privateKey, 'ed-1');

    expect(await rejection(new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs }).verify(token))).toBe(
      'unsupported algorithm',
    );

    const withEd = new JwtVerifier({ jwks: new JwksClient(uri), algorithms: ['EdDSA'], ...idp, now: nowMs });
    await expect(withEd.verify(token)).resolves.toBeTruthy();
  });

  it('verifies RS384/512, PS256/384/512, ES384 and ES512 only when enabled, with the key each one fits', async () => {
    // An identity provider's set: an RSA key with no `alg` (so it may serve RS or PS), a P-384 key
    // published for ES384, and a P-521 key.
    published = [
      jwk(keys.rsa.publicKey, 'rsa-1'),
      jwk(keys.p384.publicKey, 'p384-1', { alg: 'ES384' }),
      jwk(keys.p521.publicKey, 'p521-1'),
    ];
    const tokens = {
      PS256: sign('PS256', keys.rsa.privateKey, 'rsa-1'),
      RS512: sign('RS512', keys.rsa.privateKey, 'rsa-1'),
      ES384: sign('ES384', keys.p384.privateKey, 'p384-1'),
      ES512: sign('ES512', keys.p521.privateKey, 'p521-1'),
    };

    // The default allowlist (RS256, ES256) refuses them all before any key is looked up.
    const defaults = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    for (const token of Object.values(tokens)) {
      expect(await rejection(defaults.verify(token))).toBe('unsupported algorithm');
    }

    // Opted into, each verifies with the key of the set that fits it.
    const algorithms: JwsAlgorithm[] = ['PS256', 'RS512', 'ES384', 'ES512'];
    const enabled = new JwtVerifier({ jwks: new JwksClient(uri), algorithms, ...idp, now: nowMs });
    for (const token of Object.values(tokens)) {
      await expect(enabled.verify(token)).resolves.toMatchObject({ sub: 'u1' });
    }
    // Kid-less too: one key of the set fits each curve.
    await expect(enabled.verify(sign('ES512', keys.p521.privateKey))).resolves.toMatchObject({ sub: 'u1' });

    // A token never picks a key of another curve, whatever its kid says.
    expect(await rejection(enabled.verify(sign('ES512', keys.p521.privateKey, 'p384-1')))).toBe('no matching key');
  });

  it('keeps a JWK published as RS256 from verifying PS256, and HMAC algorithms from a JWKS', async () => {
    // A JWK's `alg` is the identity provider saying what the key is for: it narrows the RS and PS
    // algorithms an RSA key could otherwise serve, even when the verifier accepts them all.
    published = [jwk(keys.rsa.publicKey, 'rsa-1', { alg: 'RS256' })];
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), algorithms: ['RS256', 'PS256'], ...idp, now: nowMs });
    expect(await rejection(verifier.verify(sign('PS256', keys.rsa.privateKey, 'rsa-1')))).toBe('no matching key');
    await expect(verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'))).resolves.toMatchObject({ sub: 'u1' });

    // A JWKS holds public keys, and an HMAC "secret" anyone can download is no secret: refused both
    // when the verifier is created and by the client itself.
    for (const alg of ['HS384', 'HS512'] as const) {
      expect(() => new JwtVerifier({ jwks: uri, algorithms: ['RS256', alg], ...idp })).toThrow(`JwtVerifier: ${alg} cannot be combined with a JWKS.`);
      expect(await rejection(new JwksClient(uri).getKey({ alg, kid: 'rsa-1' }))).toBe('unsupported algorithm');
    }
  });
});
