/**
 * The edges of JWT verification the main suite leaves out: exact time boundaries, claim types,
 * custom required claims, `audience: false`, header fields, configuration errors; and
 * `JwtBearerProvider` on its own: header parsing, RFC 6750 challenges, `amr` and socket.io tokens;
 * and what `TokenService` puts in the tokens it signs.
 */
import { createHmac, generateKeyPairSync } from 'node:crypto';
import type { ExecutionContext } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/internal';
import {
  AuthenticationError,
  InMemoryRefreshTokenStore,
  JwtBearerProvider,
  JwtError,
  JwtSigner,
  JwtVerifier,
  TokenService,
  type JwtBearerProviderOptions,
  type JwtClaims,
} from '../lib/index.js';
import { PROVIDER_INIT } from '../lib/providers/authentication.provider.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../lib/authentication.constants.js';
import { validateClaims } from '../lib/jwt/jws.util.js';
import { storageWith } from './fixtures.js';

const NOW = 1_800_000_000;
const nowMs = () => NOW * 1000;
const SECRET = 'test-secret-that-is-at-least-32-bytes-long!';
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const headerOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
const claimsOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());

function hs256(payload: object, header: object = { alg: 'HS256', typ: 'JWT' }) {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${createHmac('sha256', SECRET).update(input).digest('base64url')}`;
}

async function refused(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(JwtError);
  return (error as Error).message;
}

const verifier = (options = {}) => new JwtVerifier({ key: SECRET, now: nowMs, ...options });

describe('JwtVerifier: time boundaries', () => {
  it('accepts a token until the second before `exp`, and refuses it at `exp`', async () => {
    await expect(verifier().verify(hs256({ exp: NOW + 1 }))).resolves.toBeTruthy();
    expect(await refused(verifier().verify(hs256({ exp: NOW })))).toBe('token expired');
  });

  it('accepts a token from `nbf` on, and an `iat` of now', async () => {
    await expect(verifier().verify(hs256({ exp: NOW + 10, nbf: NOW, iat: NOW }))).resolves.toBeTruthy();
    expect(await refused(verifier().verify(hs256({ exp: NOW + 10, nbf: NOW + 1 })))).toBe('token not yet valid');
  });

  it('extends every time check by the same leeway, and not one second further', async () => {
    const lenient = verifier({ clockTolerance: '30s' });
    await expect(lenient.verify(hs256({ exp: NOW - 29 }))).resolves.toBeTruthy();
    expect(await refused(lenient.verify(hs256({ exp: NOW - 30 })))).toBe('token expired');
    await expect(lenient.verify(hs256({ exp: NOW + 100, nbf: NOW + 30, iat: NOW + 30 }))).resolves.toBeTruthy();
    expect(await refused(lenient.verify(hs256({ exp: NOW + 100, nbf: NOW + 31 })))).toBe('token not yet valid');
    expect(await refused(lenient.verify(hs256({ exp: NOW + 100, iat: NOW + 31 })))).toBe('token issued in the future');
  });

  it('`maxAge` needs `iat`, and counts from it', async () => {
    const fresh = verifier({ maxAge: '1m' });
    await expect(fresh.verify(hs256({ exp: NOW + 10, iat: NOW - 60 }))).resolves.toBeTruthy();
    expect(await refused(fresh.verify(hs256({ exp: NOW + 10 })))).toBe('missing iat');
  });

  it('reads the clock at each verify(), in milliseconds', async () => {
    let clock = NOW * 1000;
    const ticking = new JwtVerifier({ key: SECRET, now: () => clock });
    const token = hs256({ exp: NOW + 2 });

    await expect(ticking.verify(token)).resolves.toBeTruthy();
    clock += 1_999;
    await expect(ticking.verify(token)).resolves.toBeTruthy();
    clock += 1;
    expect(await refused(ticking.verify(token))).toBe('token expired');
  });
});

describe('JwtVerifier: claims', () => {
  it('refuses registered claims of the wrong type', async () => {
    const cases: [object, string][] = [
      [{ exp: NOW + 10, nbf: 'soon' }, 'invalid nbf'],
      [{ exp: NOW + 10, iat: null }, 'invalid iat'],
      [{ exp: Number.MAX_VALUE * 10 }, 'invalid exp'], // Infinity does not survive JSON: it becomes null
      [{ exp: NOW + 10, iss: 42 }, 'invalid iss'],
      [{ exp: NOW + 10, sub: { id: 'u1' } }, 'invalid sub'],
      [{ exp: NOW + 10, jti: 7 }, 'invalid jti'],
    ];
    for (const [claims, message] of cases) {
      expect(await refused(verifier().verify(hs256(claims)))).toBe(message);
    }
  });

  it('requires the claims it is told to, in place of `exp`', async () => {
    const strict = verifier({ required: ['sub', 'jti'] });
    expect(await refused(strict.verify(hs256({ sub: 'u1' })))).toBe('missing jti');
    await expect(strict.verify(hs256({ sub: 'u1', jti: 'j1' }))).resolves.toEqual({ sub: 'u1', jti: 'j1' });
    await expect(verifier({ required: [] }).verify(hs256({ sub: 'u1' }))).resolves.toEqual({ sub: 'u1' });
  });

  it('takes one audience among several, ignores non-string entries, and skips the check with `audience: false`', async () => {
    const api = verifier({ audience: 'api' });
    await expect(api.verify(hs256({ exp: NOW + 10, aud: 'api' }))).resolves.toBeTruthy();
    await expect(api.verify(hs256({ exp: NOW + 10, aud: [1, 'api'] }))).resolves.toBeTruthy();
    expect(await refused(api.verify(hs256({ exp: NOW + 10 })))).toBe('unexpected audience');
    expect(await refused(api.verify(hs256({ exp: NOW + 10, aud: ['API'] })))).toBe('unexpected audience');

    await expect(verifier({ audience: false }).verify(hs256({ exp: NOW + 10, aud: 'anything' }))).resolves.toBeTruthy();
  });

  it('never matches a missing `iss` against an issuer list, even one the constructor would refuse', () => {
    // The constructor's check is the first line; the claim check holds on its own.
    expect(() => validateClaims({ exp: NOW + 10 }, { issuer: [undefined] as never, now: nowMs })).toThrow('unexpected issuer');
    expect(() => validateClaims({ exp: NOW + 10 }, { issuer: new Array(1) as never, now: nowMs })).toThrow('unexpected issuer');
    expect(() => validateClaims({ exp: NOW + 10, iss: 'https://idp.test' }, { issuer: [], now: nowMs })).toThrow('unexpected issuer');
  });

  it('compares `typ` without regard to case, and refuses a token without one when a type is set', async () => {
    const at = verifier({ type: 'at+jwt' });
    await expect(at.verify(hs256({ exp: NOW + 10 }, { alg: 'HS256', typ: 'AT+JWT' }))).resolves.toBeTruthy();
    expect(await refused(at.verify(hs256({ exp: NOW + 10 }, { alg: 'HS256' })))).toBe('unexpected token type');
    expect(await refused(at.verify(hs256({ exp: NOW + 10 }, { alg: 'HS256', typ: ['at+jwt'] })))).toBe('unexpected token type');
  });

  it('reads a `typ` without `/` as an `application/` media type (RFC 7515 §4.1.9), as RFC 9068 access tokens need', async () => {
    const typed = (typ: string) => hs256({ exp: NOW + 10 }, { alg: 'HS256', typ });
    for (const type of ['at+jwt', 'application/at+jwt', 'Application/AT+JWT']) {
      const accepting = verifier({ type });
      await expect(accepting.verify(typed('at+jwt'))).resolves.toBeTruthy();
      await expect(accepting.verify(typed('application/at+jwt'))).resolves.toBeTruthy();
      expect(await refused(accepting.verify(typed('jwt')))).toBe('unexpected token type');
      expect(await refused(accepting.verify(typed('text/at+jwt')))).toBe('unexpected token type');
    }
  });

  it('refuses a header without an `alg` string as malformed, before anything else', async () => {
    expect(await refused(verifier().verify(hs256({ exp: NOW + 10 }, { typ: 'JWT' })))).toBe('malformed token');
    expect(await refused(verifier().verify(hs256({ exp: NOW + 10 }, { alg: 256 })))).toBe('malformed token');
    expect(await refused(verifier().verify(`${b64({ alg: 'HS256' })}.${Buffer.from('not json').toString('base64url')}.c2ln`))).toBe(
      'malformed token',
    );
    expect(await refused(verifier().verify(`${b64({ alg: 'HS256' })}.${b64('a string')}.c2ln`))).toBe('malformed token');
  });
});

describe('JwtVerifier and JwtSigner: configuration', () => {
  it('needs exactly one of `key` and `jwks`', () => {
    expect(() => new JwtVerifier({})).toThrow('JwtVerifier: pass exactly one of `key` or `jwks`.');
    expect(() => new JwtVerifier({ key: SECRET, jwks: 'https://idp.test/jwks' })).toThrow(/exactly one/);
  });

  it('verifies with the public half of a private key', async () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const token = new JwtSigner({ key: pair.privateKey, now: nowMs }).sign({ sub: 'u1' });
    await expect(new JwtVerifier({ key: pair.privateKey, now: nowMs }).verify(token)).resolves.toMatchObject({ sub: 'u1' });
  });

  it('refuses keys of a type no algorithm uses, and PEM text it cannot read', () => {
    const x25519 = generateKeyPairSync('x25519');
    expect(() => new JwtVerifier({ key: x25519.publicKey })).toThrow('JwtVerifier: x25519 keys are not supported.');
    expect(() => new JwtSigner({ key: x25519.privateKey })).toThrow('JwtSigner: x25519 keys are not supported.');

    const broken = '-----BEGIN PUBLIC KEY-----\nnot base64 at all\n-----END PUBLIC KEY-----';
    expect(() => new JwtVerifier({ key: broken })).toThrow(/^Cannot read the PEM public key: /);
  });

  it('refuses a JWK passed as text, which would otherwise be an HS256 secret anyone holding the public key knows', async () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const publicJwk = JSON.stringify(pair.publicKey.export({ format: 'jwk' }));
    const privateJwk = JSON.stringify(pair.privateKey.export({ format: 'jwk' }));

    expect(() => new JwtVerifier({ key: publicJwk })).toThrow(/^The key is a JWK, which would be read as an HS256 secret/);
    expect(() => new JwtVerifier({ key: Buffer.from(` \n${publicJwk}`) })).toThrow(/is a JWK/);
    expect(() => new JwtSigner({ key: privateJwk })).toThrow(/is a JWK/);

    // Text that only looks like JSON is still a secret.
    expect(() => new JwtVerifier({ key: '{ not JSON at all, only a secret of 32+ bytes }' })).not.toThrow();
    const secret = '{"not":"a key","padding":"to reach thirty-two bytes"}';
    const token = new JwtSigner({ key: secret, now: nowMs }).sign({ sub: 'u1' });
    await expect(new JwtVerifier({ key: secret, now: nowMs }).verify(token)).resolves.toMatchObject({ sub: 'u1' });
  });

  it('names what each algorithm needs', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(() => new JwtVerifier({ key: rsa.publicKey, algorithms: ['ES256'] })).toThrow(
      'JwtVerifier: the key is not a valid ES256 key; ES256 needs a P-256 key.',
    );
    expect(() => new JwtVerifier({ key: 'x'.repeat(31) })).toThrow(
      'JwtVerifier: the key is not a valid HS256 key; HS256 needs a secret of at least 32 bytes (`openssl rand -base64 32`).',
    );
    expect(() => new JwtSigner({ key: rsa.privateKey, alg: 'EdDSA' })).toThrow('JwtSigner: the key is not a valid EdDSA key; EdDSA needs an Ed25519 key.');
  });

  it('puts `kid` and `typ` in the header, and `iss`, `aud` and a fresh `jti` in the claims', () => {
    const signer = new JwtSigner({ key: SECRET, kid: 'k7', type: 'at+jwt', issuer: 'https://api.test', audience: ['a', 'b'], now: nowMs });
    const first = signer.sign({ sub: 'u1' });

    expect(headerOf(first)).toEqual({ alg: 'HS256', typ: 'at+jwt', kid: 'k7' });
    expect(claimsOf(first)).toEqual({ iss: 'https://api.test', aud: ['a', 'b'], jti: expect.stringMatching(/^[\w-]{22}$/), sub: 'u1', iat: NOW, exp: NOW + 900 });
    expect(claimsOf(signer.sign({ sub: 'u1' })).jti).not.toBe(claimsOf(first).jti);
  });

  it('lets callers set `jti`, `iss` and `aud`, but never `iat` or `exp`', () => {
    const signer = new JwtSigner({ key: SECRET, issuer: 'https://api.test', now: nowMs, ttl: '1m' });
    const claims = claimsOf(signer.sign({ jti: 'mine', iss: 'https://other.test', aud: 'x', iat: 1, exp: 2 }));
    expect(claims).toEqual({ jti: 'mine', iss: 'https://other.test', aud: 'x', iat: NOW, exp: NOW + 60 });
  });
});

describe('JwtBearerProvider', () => {
  class Bearer extends JwtBearerProvider<{ id: string }> {
    readonly seen: JwtClaims[] = [];
    constructor(
      options: JwtBearerProviderOptions = { key: SECRET, now: nowMs },
      private readonly users: Record<string, { id: string }> = { u1: { id: 'u1' } },
    ) {
      super(options);
    }
    validate(claims: JwtClaims) {
      this.seen.push(claims);
      return this.users[claims.sub!];
    }
  }

  class Handler {
    handle() {}
  }
  const http = (headers: Record<string, string | string[]>): ExecutionContext => {
    const ctx = new ExecutionContextHost([{ headers }, {}], Handler, Handler.prototype.handle);
    ctx.setType('http');
    return ctx;
  };
  const ws = (client: object): ExecutionContext => {
    const ctx = new ExecutionContextHost([client, {}], Handler, Handler.prototype.handle);
    ctx.setType('ws');
    return ctx;
  };
  const token = (claims: object = { sub: 'u1', exp: NOW + 60 }) => hs256(claims);

  async function rejection(promise: Promise<unknown>): Promise<AuthenticationError> {
    const error = await promise.then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(AuthenticationError);
    return error as AuthenticationError;
  }

  it('reads the Bearer scheme in any case, with any whitespace around the token', async () => {
    const provider = new Bearer();
    for (const authorization of [`Bearer ${token()}`, `bearer ${token()}`, `BEARER   ${token()}  `, `\tBearer\t${token()}`]) {
      await expect(provider.authenticate(http({ authorization }))).resolves.toMatchObject({ user: { id: 'u1' } });
    }
  });

  it('leaves requests without a header, and other schemes, to the next provider', async () => {
    const provider = new Bearer();
    await expect(provider.authenticate(http({}))).resolves.toBeNull();
    await expect(provider.authenticate(http({ authorization: 'Basic dTE6cHc=' }))).resolves.toBeNull();
    await expect(provider.authenticate(http({ authorization: `Token ${token()}` }))).resolves.toBeNull();
    expect(provider.seen).toEqual([]);
  });

  it('answers a Bearer header without exactly one token with an RFC 6750 invalid_token challenge', async () => {
    const provider = new Bearer(undefined);
    for (const authorization of ['Bearer', 'Bearer   ', `Bearer ${token()} extra`]) {
      const error = await rejection(provider.authenticate(http({ authorization })));
      expect(error.message).toBe('malformed authorization header');
      expect(error.challenge).toBe('Bearer realm="api", error="invalid_token", error_description="malformed authorization header"');
    }
  });

  it('turns each verification failure into a 401 naming it, in the realm it was given', async () => {
    const provider = new Bearer({ key: SECRET, now: nowMs, realm: 'admin' });
    expect(provider.challenge()).toBe('Bearer realm="admin"');

    const expired = await rejection(provider.authenticate(http({ authorization: `Bearer ${token({ sub: 'u1', exp: NOW })}` })));
    expect(expired).not.toBeInstanceOf(JwtError); // the guard's refusal, not the verifier's
    expect(expired).toMatchObject({
      status: 401,
      message: 'token expired',
      challenge: 'Bearer realm="admin", error="invalid_token", error_description="token expired"',
    });

    const garbage = await rejection(provider.authenticate(http({ authorization: 'Bearer not-a-jwt' })));
    expect(garbage.message).toBe('malformed token');
  });

  it('refuses a verified token whose subject is gone, and passes the claims to validate() otherwise', async () => {
    const provider = new Bearer();
    const gone = await rejection(provider.authenticate(http({ authorization: `Bearer ${token({ sub: 'u9', exp: NOW + 60 })}` })));
    expect(gone.challenge).toBe('Bearer realm="api", error="invalid_token", error_description="unknown subject"');

    const result = await provider.authenticate(http({ authorization: `Bearer ${token({ sub: 'u1', exp: NOW + 60, scope: 'read' })}` }));
    expect(result).toEqual({ user: { id: 'u1' }, session: { sub: 'u1', exp: NOW + 60, scope: 'read' }, mfa: undefined });
    expect(provider.seen.at(-1)).toEqual({ sub: 'u1', exp: NOW + 60, scope: 'read' });
  });

  it('marks tokens whose `amr` names a second factor as MFA-verified, and only those', async () => {
    const provider = new Bearer();
    const mfaOf = async (amr: unknown) =>
      (await provider.authenticate(http({ authorization: `Bearer ${token({ sub: 'u1', exp: NOW + 60, amr })}` })))!.mfa;

    expect(await mfaOf(['pwd', 'otp'])).toBe('verified');
    expect(await mfaOf(['hwk'])).toBe('verified');
    expect(await mfaOf(['pwd'])).toBeUndefined();
    expect(await mfaOf('mfa')).toBeUndefined();
  });

  it('reads the first of repeated Authorization headers', async () => {
    const provider = new Bearer();
    await expect(provider.authenticate(http({ authorization: [`Bearer ${token()}`, 'Basic x'] }))).resolves.toMatchObject({
      user: { id: 'u1' },
    });
  });

  it('takes socket.io’s `handshake.auth.token` when the handshake has no Authorization header', async () => {
    const provider = new Bearer();
    await expect(provider.authenticate(ws({ handshake: { headers: {}, auth: { token: token() } } }))).resolves.toMatchObject({
      user: { id: 'u1' },
    });
    await expect(provider.authenticate(ws({ handshake: { headers: {}, auth: { token: 42 } } }))).resolves.toBeNull();
    await expect(provider.authenticate(ws({ handshake: { headers: {} } }))).resolves.toBeNull();

    // The header wins over the auth payload.
    await expect(
      provider.authenticate(ws({ handshake: { headers: { authorization: 'Bearer x.y' }, auth: { token: token() } } })),
    ).rejects.toMatchObject({ message: 'malformed token' });
  });

  it('without `key` or `jwks`, verifies what the module’s `accessToken` issues, and fails at startup without it', async () => {
    const signer = { key: SECRET, issuer: 'https://api.test', audience: 'api', now: nowMs };
    const issued = new JwtSigner(signer).sign({ sub: 'u1' });

    const configured = new Bearer({});
    configured[PROVIDER_INIT](((token: unknown) => (token === AUTHENTICATION_MODULE_OPTIONS ? { accessToken: signer } : undefined)) as never);
    await expect(configured.authenticate(http({ authorization: `Bearer ${issued}` }))).resolves.toMatchObject({ user: { id: 'u1' } });

    // The module's issuer and audience apply: a token of the same key for another audience fails.
    const other = new JwtSigner({ ...signer, audience: 'other' }).sign({ sub: 'u1' });
    await expect(configured.authenticate(http({ authorization: `Bearer ${other}` }))).rejects.toMatchObject({
      message: 'unexpected audience',
    });

    const unconfigured = new Bearer({});
    expect(() => unconfigured[PROVIDER_INIT]((() => undefined) as never)).toThrow(
      'Bearer: nothing to verify tokens with. Configure `accessToken` in the AuthenticationModule options, or pass `key` or `jwks` to super().',
    );
  });

  it('refuses a `key` or `jwks` given but empty, rather than take the app’s own tokens as the partner’s', async () => {
    // `super({ key: process.env.PARTNER_KEY })` with the variable unset.
    expect(() => new Bearer({ key: process.env.NO_SUCH_PARTNER_KEY })).toThrow(
      'Bearer: `key` is empty: is the environment variable it reads set? Leave both out to verify the tokens the module’s `accessToken` issues.'.replace('’', "'"),
    );
    expect(() => new Bearer({ jwks: '' })).toThrow(/^Bearer: `jwks` is empty/);
    expect(() => new Bearer({ key: undefined, jwks: undefined })).toThrow(/^Bearer: `key` and `jwks` are empty/);
    expect(() => new Bearer({ key: undefined, jwks: 'https://idp.test/jwks', issuer: 'https://idp.test', audience: 'api' })).not.toThrow();
  });

  it('lets options passed to super() add rules to the module’s `accessToken`', async () => {
    const signer = { key: SECRET, now: nowMs };
    const provider = new Bearer({ maxAge: '1m' });
    provider[PROVIDER_INIT]((() => ({ accessToken: signer })) as never);

    const old = hs256({ sub: 'u1', exp: NOW + 600, iat: NOW - 120 });
    await expect(provider.authenticate(http({ authorization: `Bearer ${old}` }))).rejects.toMatchObject({ message: 'token too old' });
  });

  it('takes a list of issuers, its own or in place of the module’s `accessToken` issuer', async () => {
    const issued = (iss?: string) => `Bearer ${token({ sub: 'u1', exp: NOW + 60, ...(iss !== undefined && { iss }) })}`;

    const own = new Bearer({ key: SECRET, issuer: ['https://idp.test', 'idp.test'], now: nowMs });
    await expect(own.authenticate(http({ authorization: issued('idp.test') }))).resolves.toMatchObject({ user: { id: 'u1' } });
    expect((await rejection(own.authenticate(http({ authorization: issued('https://evil.test') })))).message).toBe('unexpected issuer');
    expect((await rejection(own.authenticate(http({ authorization: issued() })))).message).toBe('unexpected issuer');

    // An app moving to a new issuer name accepts tokens of both while the old ones expire.
    const renamed = new Bearer({ issuer: ['https://old.test', 'https://new.test'] });
    renamed[PROVIDER_INIT]((() => ({ accessToken: { key: SECRET, issuer: 'https://new.test', now: nowMs } })) as never);
    await expect(renamed.authenticate(http({ authorization: issued('https://old.test') }))).resolves.toMatchObject({ user: { id: 'u1' } });
    await expect(renamed.authenticate(http({ authorization: issued('https://new.test') }))).resolves.toMatchObject({ user: { id: 'u1' } });
    expect((await rejection(renamed.authenticate(http({ authorization: issued('https://other.test') })))).message).toBe('unexpected issuer');
  });
});

describe('TokenService claims and inputs', () => {
  const service = (refreshTokens = new InMemoryRefreshTokenStore()) =>
    new TokenService(storageWith({ refreshTokens }), { accessToken: { key: SECRET, issuer: 'https://api.test', ttl: '2m' } });

  it('always signs the user as `sub`, whatever the claims say, on issue and on every refresh', async () => {
    const tokens = service();
    const pair = await tokens.issue('u1', { claims: { sub: 'admin', role: 'viewer' } });
    expect(claimsOf(pair.accessToken)).toMatchObject({ sub: 'u1', role: 'viewer', iss: 'https://api.test' });
    expect(claimsOf((await tokens.refresh(pair.refreshToken)).accessToken).sub).toBe('u1');
    expect(pair.expiresIn).toBe(120);
  });

  it('refuses refresh tokens that are not well-formed as invalid, without a lookup', async () => {
    const store = new InMemoryRefreshTokenStore();
    const lookup = vi.spyOn(store, 'getRefreshToken');
    const tokens = service(store);

    for (const token of [undefined, 42, '', 'short', 'A'.repeat(44), `${'A'.repeat(42)}=`]) {
      await expect(tokens.refresh(token as never)).rejects.toMatchObject({ name: 'RefreshTokenError', reason: 'invalid' });
      await expect(tokens.revoke(token as never)).resolves.toBe(false);
    }
    expect(lookup).not.toHaveBeenCalled();
  });

  it('names `accessToken.key` when it arrives undefined, and the problem when it cannot sign', () => {
    expect(() => new TokenService(storageWith(), { accessToken: { key: undefined as never } })).toThrow(
      'AuthenticationModule: `accessToken.key` is required (a secret of at least 32 bytes or a KeyObject), but it is undefined',
    );
    const publicKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    expect(() => new TokenService(storageWith(), { accessToken: { key: publicKey } })).toThrow(
      'AuthenticationModule: `accessToken`: ES256 signing needs a private key.',
    );
  });
});
