import { AsyncLocalStorage } from 'node:async_hooks';
import { Logger, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { HttpAdapterHost, Reflector } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/internal';
import { setTimeout as sleep } from 'node:timers/promises';
import { lastValueFrom, throwError } from 'rxjs';
import {
  Authenticate,
  AuthenticationContext,
  AuthenticationError,
  AuthenticationEvents,
  AuthenticationGuard,
  AuthenticationProvider,
  InMemoryEmailTokenStore,
  InMemoryMagicLinkStore,
  InMemoryMfaStore,
  InMemoryOidcStateStore,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  JwtBearerProvider,
  JwtError,
  MagicLinkHandler,
  MagicLinkError,
  MagicLinkService,
  MfaAlreadyEnrolledError,
  MfaService,
  PasswordHasher,
  Public,
  RefreshTokenError,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationEvent,
  type AuthenticationResult,
  type Duration,
  type JwtClaims,
  type MagicLinkOptions,
} from '../lib/index.js';
import { AuthenticationScopeInterceptor } from '../lib/interceptors/authentication-scope.interceptor.js';
import { AuthenticationScope } from '../lib/context/authentication-scope.service.js';
import { sha256, safeRedirectPath } from '../lib/utils/crypto.util.js';
import { toMs } from '../lib/utils/duration.util.js';
import { AuthenticationRegistry } from '../lib/services/authentication-registry.service.js';
import { SecretCipher } from '../lib/mfa/secret-cipher.service.js';
import { encodePassword } from '../lib/services/password-hasher.service.js';
import { base32Decode, base32Encode, hotp } from '../lib/mfa/otp.util.js';
import { readCookie } from '../lib/session/cookies.util.js';
import { registryWith, storageWith } from './fixtures.js';

const SECRET = 'test-secret-that-is-at-least-32-bytes-long!';
const claimsOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

describe('PasswordHasher (scrypt)', () => {
  const fast = new PasswordHasher({ logN: 10 });

  it('hashes to a self-describing string and verifies', async () => {
    const hash = await fast.hash('correct horse');
    expect(hash).toMatch(/^\$scrypt\$ln=10,r=8,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    await expect(fast.verify('correct horse', hash)).resolves.toBe(true);
    await expect(fast.verify('correct horsE', hash)).resolves.toBe(false);
    expect(await fast.hash('correct horse')).not.toBe(hash); // salted
  });

  it('uses OWASP parameters by default (N=2^17)', async () => {
    const hash = await new PasswordHasher().hash('pw');
    expect(hash.startsWith('$scrypt$ln=17,r=8,p=1$')).toBe(true);
    await expect(new PasswordHasher().verify('pw', hash)).resolves.toBe(true);
  });

  it('verifies with the parameters stored in the hash, and flags weaker ones for rehash', async () => {
    const old = await fast.hash('pw');
    const current = new PasswordHasher({ logN: 11 });
    await expect(current.verify('pw', old)).resolves.toBe(true);
    expect(current.needsRehash(old)).toBe(true);
    expect(current.needsRehash(await current.hash('pw'))).toBe(false);
  });

  it('normalises Unicode (NFKC)', async () => {
    const hash = await fast.hash('café'); // precomposed
    await expect(fast.verify('café', hash)).resolves.toBe(true); // combining accent
  });

  it('rejects malformed, tampered and absurd hashes without throwing', async () => {
    const hash = await fast.hash('pw');
    const [, , , salt] = hash.split('$');
    const derived = (bytes: number) => `$scrypt$ln=10,r=8,p=1$${salt}$${Buffer.alloc(bytes, 1).toString('base64').replace(/=+$/, '')}`;
    for (const bad of ['', 'plain', hash.replace('ln=10', 'ln=40'), hash.replace('$scrypt$', '$bcrypt$'), `${hash}x!`, derived(15), derived(65)]) {
      await expect(fast.verify('pw', bad)).resolves.toBe(false);
      expect(fast.needsRehash(bad)).toBe(true);
    }
  });

  it('refuses empty passwords, those over 4 KiB and non-strings: hash() throws, verify() answers false without deriving', async () => {
    const hasher = new PasswordHasher({ logN: 10 });
    const hash = await hasher.hash('pw');
    const derive = vi.spyOn(hasher as unknown as { derive(...args: unknown[]): Promise<Buffer> }, 'derive');

    const long = 'x'.repeat(4097);
    await expect(hasher.hash(long)).rejects.toThrow(new RangeError('password too long'));
    await expect(hasher.hash('')).rejects.toThrow(new RangeError('password is empty'));
    await expect(hasher.hash(42 as never)).rejects.toThrow(new TypeError('password must be a string'));
    await expect(hasher.verify(long, hash)).resolves.toBe(false);
    await expect(hasher.verify('', hash)).resolves.toBe(false);
    await expect(hasher.verify(undefined as never, hash)).resolves.toBe(false);
    expect(derive).not.toHaveBeenCalled(); // a megabyte password costs nothing

    // The limit counts UTF-8 bytes after normalisation: 1,366 three-byte characters are 4,098.
    await expect(hasher.hash('€'.repeat(1366))).rejects.toThrow('password too long');
    await expect(hasher.verify('€'.repeat(1365), await hasher.hash('€'.repeat(1365)))).resolves.toBe(true);
  });

  it('refuses unsupported parameters up front', () => {
    expect(() => new PasswordHasher({ logN: 30 })).toThrow(RangeError);
    // A fraction would fail every hash(), and lengths `parse()` refuses would never verify.
    expect(() => new PasswordHasher({ logN: 10.5 })).toThrow('PasswordHasher: unsupported scrypt parameters');
    expect(() => new PasswordHasher({ logN: 22, r: 8 })).toThrow('PasswordHasher: unsupported scrypt parameters'); // 4 GiB
    expect(() => new PasswordHasher({ keyLength: 8 })).toThrow('PasswordHasher: `keyLength` must be an integer from 16 to 64 bytes, got 8');
    expect(() => new PasswordHasher({ keyLength: 65 })).toThrow(/`keyLength` must be an integer from 16 to 64/);
    expect(() => new PasswordHasher({ saltLength: 0 })).toThrow('PasswordHasher: `saltLength` must be an integer from 16 to 64 bytes, got 0');
    expect(() => new PasswordHasher({ saltLength: 16.5 })).toThrow(/`saltLength` must be an integer/);
    expect(() => new PasswordHasher({ logN: 20, r: 8, keyLength: 64, saltLength: 64 })).not.toThrow(); // 1 GiB: the most
  });

  it('refuses stored hashes that would demand more than the bounds, or carry a salt over 64 bytes', async () => {
    const hash = await fast.hash('pw');
    const [, , , salt, key] = hash.split('$');
    const stored = (params: string, saltPart = salt) => `$scrypt$${params}$${saltPart}$${key}`;

    const derive = vi.spyOn(fast as unknown as { derive(...args: unknown[]): Promise<Buffer> }, 'derive');
    try {
      for (const tampered of [stored('ln=22,r=32,p=16'), stored('ln=20,r=16,p=1'), stored('ln=17,r=8,p=16', Buffer.alloc(65).toString('base64').replace(/=+$/, ''))]) {
        await expect(fast.verify('pw', tampered)).resolves.toBe(false);
        // Only the dummy's work: never the parameters the row asked for.
        for (const [, , , params] of derive.mock.calls) {
          expect(params).toEqual({ logN: 10, r: 8, p: 1 });
        }
      }
    } finally {
      derive.mockRestore();
    }
  });

  it('spends the dummy’s work on a stored hash it cannot read, as on an unknown user', async () => {
    const hasher = new PasswordHasher({ logN: 10 });
    await hasher.verify('pw', undefined); // makes the dummy
    const derive = vi.spyOn(hasher as unknown as { derive(...args: unknown[]): Promise<Buffer> }, 'derive');

    // A disabled account, a hash from another scheme, a truncated one.
    for (const unreadable of ['!', '*', '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW', '$scrypt$ln=10']) {
      await expect(hasher.verify('pw', unreadable)).resolves.toBe(false);
    }
    expect(derive).toHaveBeenCalledTimes(4);
  });

  it('forgets a dummy hash that failed, so the next unknown user tries again rather than failing forever', async () => {
    const hasher = new PasswordHasher({ logN: 10 });
    const derive = vi.spyOn(hasher as unknown as { derive(...args: unknown[]): Promise<Buffer> }, 'derive');
    derive.mockRejectedValueOnce(new Error('thread pool busy'));

    await expect(hasher.verify('pw', undefined)).rejects.toThrow('thread pool busy');
    await expect(hasher.verify('pw', undefined)).resolves.toBe(false);
  });

  it('refuses an over-long password before normalising it, which can multiply its length', () => {
    // U+FDFA is one UTF-16 unit and 18 characters in NFKC.
    const normalize = vi.spyOn(String.prototype, 'normalize');
    try {
      expect(() => encodePassword('ﷺ'.repeat(4097))).toThrow(new RangeError('password too long'));
      expect(normalize).not.toHaveBeenCalled();
    } finally {
      normalize.mockRestore();
    }
  });

  it('spends the same work for unknown users, from the first request on', async () => {
    const hasher = new PasswordHasher({ logN: 10 });
    const derive = vi.spyOn(hasher as unknown as { derive(...args: unknown[]): Promise<Buffer> }, 'derive');

    await expect(hasher.verify('pw', undefined)).resolves.toBe(false);
    expect(derive).toHaveBeenCalledTimes(1); // the dummy hash is the work, not an extra step

    await expect(hasher.verify('pw', undefined)).resolves.toBe(false);
    await expect(hasher.verify('pw', await fast.hash('other'))).resolves.toBe(false);
    expect(derive).toHaveBeenCalledTimes(3); // one derivation per check
  });
});

describe('TOTP', () => {
  it('matches the RFC 4226 and RFC 6238 test vectors', () => {
    const key = Buffer.from('12345678901234567890');
    expect([0, 1, 2, 9].map((c) => hotp(key, c))).toEqual(['755224', '287082', '359152', '520489']);

    // RFC 6238 Appendix B (SHA-1, 8 digits)
    expect(hotp(key, Math.floor(59 / 30), 8)).toBe('94287082');
    expect(hotp(key, Math.floor(1111111109 / 30), 8)).toBe('07081804');
    expect(hotp(key, Math.floor(20000000000 / 30), 8)).toBe('65353130');
  });

  it('round-trips base32', () => {
    const data = Buffer.from('any bytes ÿ');
    expect(base32Decode(base32Encode(data))).toEqual(data);
    expect(base32Encode(Buffer.from('foobar'))).toBe('MZXW6YTBOI'); // RFC 4648 §10, unpadded
  });

  function setup(options: { lockoutWindow?: '1m'; window?: number } = {}) {
    let clock = 1_700_000_000_000;
    const store = new InMemoryMfaStore();
    const events = new AuthenticationEvents();
    const seen: AuthenticationEvent[] = [];
    events.events$.subscribe((event) => seen.push(event));

    const mfa = new MfaService(
      storageWith({ mfa: store }),
      { mfa: { now: () => clock, encryption: { keys: ['k'.repeat(32)] }, ...options } },
      events,
    );

    const code = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(clock / 30_000) + offset);
    return { mfa, code, seen, tick: (ms: number) => (clock += ms) };
  }

  it('enrolls, confirms, and accepts ±1 step but not ±2', async () => {
    const { mfa, code } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    expect(base32Decode(secret)).toHaveLength(20);

    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(false); // not confirmed yet

    await expect(mfa.confirm('u1', code(secret, -1))).resolves.toBe(true);
    await expect(mfa.isEnrolled('u1')).resolves.toBe(true);

    await expect(mfa.verifyTotp('u1', code(secret, 2))).resolves.toBe(false);
    await expect(mfa.verifyTotp('u1', code(secret, 1))).resolves.toBe(true);
  });

  it('never accepts a step at or before the last used one', async () => {
    const { mfa, code, tick } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(secret, 1));

    await expect(mfa.verifyTotp('u1', code(secret, 1))).resolves.toBe(false); // replay
    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(false); // older step

    tick(60_000);
    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(true);
  });

  it('locks verification after repeated failures, then recovers after `lockoutWindow`', async () => {
    const { mfa, code, tick } = setup({ lockoutWindow: '1m' });
    const { secret } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(secret));

    tick(30_000);
    for (let i = 0; i < 5; i++) {
      await mfa.verifyTotp('u1', '000000');
    }

    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(false); // right code, locked

    tick(60_000);
    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(true);
  });

  it('accepts only the current step with `window: 0`', async () => {
    const { mfa, code, tick } = setup({ window: 0 });
    const { secret } = await mfa.enroll('u1', 'alice');
    await expect(mfa.confirm('u1', code(secret, -1))).resolves.toBe(false);
    await expect(mfa.confirm('u1', code(secret, 1))).resolves.toBe(false);
    await expect(mfa.confirm('u1', code(secret))).resolves.toBe(true);

    tick(30_000);
    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(true);
  });

  it('refuses at startup the limits that a missing environment variable would switch off', () => {
    const configure = (options: object) => () =>
      new MfaService(storageWith({ mfa: new InMemoryMfaStore() }), { mfa: { encryption: false, ...options } });

    // `Number(process.env.X)` of an unset variable: no count ever reaches a `NaN` limit.
    expect(configure({ maxAttempts: Number(process.env.NO_SUCH_LIMIT) })).toThrow(
      'AuthenticationModule: `mfa.maxAttempts` must be an integer of at least 1, but it is NaN: is the environment variable it reads set?',
    );
    expect(configure({ maxAttempts: 0 })).toThrow('`mfa.maxAttempts` must be an integer of at least 1, but it is 0.');
    expect(configure({ maxAttempts: '5' })).toThrow('`mfa.maxAttempts` must be an integer of at least 1, but it is "5".');
    // Seconds where steps are meant, fractions and negatives.
    expect(configure({ window: 30 })).toThrow('AuthenticationModule: `mfa.window` must be an integer from 0 to 10, but it is 30.');
    expect(configure({ window: 1.5 })).toThrow(/`mfa.window` must be an integer from 0 to 10/);
    expect(configure({ window: -1 })).toThrow(/`mfa.window` must be an integer from 0 to 10/);
    expect(configure({ recoveryCodes: 0 })).toThrow('`mfa.recoveryCodes` must be an integer of at least 1, but it is 0.');

    expect(configure({ maxAttempts: 1, window: 10, recoveryCodes: 1 })).not.toThrow();
  });

  it('counts each guess before checking it: a burst of parallel guesses cannot outrun the lockout', async () => {
    const { mfa, code } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(secret));

    const valid = new Set([-1, 0, 1].map((offset) => code(secret, offset)));
    const wrong = Array.from({ length: 20 }, (_, i) => String(i).padStart(6, '0')).filter((c) => !valid.has(c));
    const burst = [...wrong.slice(0, 10), code(secret, 1)]; // the right code, as the 11th guess

    const results = await Promise.all(burst.map((guess) => mfa.verifyTotp('u1', guess)));
    expect(results).toEqual(burst.map(() => false)); // only the first 5 were checked
  });

  it('counts parallel recovery-code guesses the same way', async () => {
    const { mfa } = setup();
    const [right] = await mfa.generateRecoveryCodes('u1');

    const burst = [...Array.from({ length: 10 }, (_, i) => `WRONG-CODE${i}`), right];
    const results = await Promise.all(burst.map((guess) => mfa.verifyRecoveryCode('u1', guess)));

    expect(results).toEqual(burst.map(() => false));
    await expect(mfa.remainingRecoveryCodes('u1')).resolves.toBe(10); // not spent by the refused guess
  });

  it('enroll() refuses to replace a confirmed authenticator', async () => {
    const { mfa, code, tick } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(secret));

    await expect(mfa.enroll('u1', 'alice')).rejects.toBeInstanceOf(MfaAlreadyEnrolledError);
    await expect(mfa.isEnrolled('u1')).resolves.toBe(true); // MFA was not switched off

    tick(30_000);
    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(true); // same authenticator
  });

  it('replace: true stages a new authenticator; the current one works until it is confirmed', async () => {
    const { mfa, code, tick } = setup();
    const { secret: old } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(old));

    const { secret: next } = await mfa.enroll('u1', 'alice', { replace: true });
    expect(next).not.toBe(old);
    await expect(mfa.isEnrolled('u1')).resolves.toBe(true);

    tick(30_000);
    await expect(mfa.verifyTotp('u1', code(next))).resolves.toBe(false); // not active yet
    await expect(mfa.verifyTotp('u1', code(old))).resolves.toBe(true);

    tick(30_000);
    await expect(mfa.confirm('u1', code(old))).resolves.toBe(false); // must be a code of the new one

    tick(30_000);
    await expect(mfa.confirm('u1', code(next))).resolves.toBe(true);

    tick(30_000);
    await expect(mfa.verifyTotp('u1', code(old))).resolves.toBe(false);
    await expect(mfa.verifyTotp('u1', code(next))).resolves.toBe(true);
    await expect(mfa.confirm('u1', code(next, 1))).resolves.toBe(false); // nothing pending
  });

  it('a confirm() racing disable() leaves the authenticator disabled', async () => {
    const { mfa, code } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    // disable() lands between the code check and the write that confirms.
    const store = (mfa as unknown as { store: InMemoryMfaStore }).store;
    const claim = store.claimTotpStep.bind(store);
    vi.spyOn(store, 'claimTotpStep').mockImplementation(async (userId, step) => {
      const claimed = await claim(userId, step);
      await mfa.disable(userId);
      return claimed;
    });

    await expect(mfa.confirm('u1', code(secret))).resolves.toBe(false);
    await expect(mfa.isEnrolled('u1')).resolves.toBe(false);
    await expect(store.getTotp('u1')).resolves.toBeUndefined();
  });

  it('refuses codes of other forms before any check, counting each as a guess', async () => {
    const { mfa, code, seen } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(secret));
    seen.length = 0;

    const current = code(secret, 1);
    const arabicIndic = [...current].map((d) => String.fromCharCode(0x0660 + Number(d))).join('');
    for (const guess of [arabicIndic, ` ${current}`, `${current}0`, Number(current), [current]] as never[]) {
      await expect(mfa.verifyTotp('u1', guess)).resolves.toBe(false);
    }
    expect(seen.filter((event) => event.type === 'mfa-failed')).toHaveLength(5);
  });

  it('counts a store’s truthy `confirmed` (a 1 from the database) as enrolled: the second factor is not skipped', async () => {
    const store = new InMemoryMfaStore();
    const mfa = new MfaService(storageWith({ mfa: store }), { mfa: { encryption: false } });
    await store.saveTotp('u1', { secret: base32Encode(Buffer.alloc(20, 1)), confirmed: 1 as never });
    await expect(mfa.isEnrolled('u1')).resolves.toBe(true);
  });

  it('after disable(), enrolling starts over', async () => {
    const { mfa, code } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(secret));
    await mfa.disable('u1');

    await expect(mfa.enroll('u1', 'alice')).resolves.toMatchObject({ secret: expect.any(String) });
    await expect(mfa.isEnrolled('u1')).resolves.toBe(false);
  });

  it('recovery codes are single-use, case- and dash-insensitive, stored hashed', async () => {
    const { mfa } = setup();
    const codes = await mfa.generateRecoveryCodes('u1');
    expect(codes).toHaveLength(10);
    expect(codes[0]).toMatch(/^[2-9A-Z]{5}-[2-9A-Z]{5}$/);

    await expect(mfa.verifyRecoveryCode('u1', codes[0].replace('-', ' ').toLowerCase())).resolves.toBe(true);
    await expect(mfa.verifyRecoveryCode('u1', codes[0])).resolves.toBe(false);
    await expect(mfa.remainingRecoveryCodes('u1')).resolves.toBe(9);
  });

  it('hashes recovery codes slowly and per user, so a store dump cannot be cracked at SHA-256 speed', async () => {
    const store = new InMemoryMfaStore();
    const mfa = new MfaService(storageWith({ mfa: store }), { mfa: { encryption: false } });
    const codes = await mfa.generateRecoveryCodes('u1');

    const stored: string[] = [...(store as unknown as { codes: Map<string, Set<string>> }).codes.get('u1')!];
    const fast = new Set(codes.map((c) => sha256(c.replace('-', ''))));
    expect(stored.filter((hash) => fast.has(hash))).toEqual([]);

    // Bound to the user: the same hashes in another user's row match none of their guesses.
    await store.saveRecoveryCodes('u2', stored);
    await expect(mfa.verifyRecoveryCode('u2', codes[1])).resolves.toBe(false);
    await expect(mfa.verifyRecoveryCode('u1', codes[1])).resolves.toBe(true);
  });

  it('publishes an audit event for every second-factor change and outcome', async () => {
    const { mfa, code, seen, tick } = setup();
    const { secret } = await mfa.enroll('u1', 'alice');
    await mfa.confirm('u1', code(secret));
    const [recovery] = await mfa.generateRecoveryCodes('u1');

    tick(30_000);
    await mfa.verifyTotp('u1', code(secret));
    await mfa.verifyRecoveryCode('u1', recovery);

    for (let i = 0; i < 5; i++) {
      await mfa.verifyTotp('u1', '000000');
    }
    await mfa.verifyRecoveryCode('u1', 'AAAAA-AAAAA'); // refused unchecked: locked out

    const { secret: next } = await mfa.enroll('u1', 'alice', { replace: true });
    tick(15 * 60_000);
    await mfa.confirm('u1', code(next));
    await mfa.disable('u1');

    expect(seen).toEqual([
      { type: 'mfa-enabled', userId: 'u1', replaced: false },
      { type: 'recovery-codes-generated', userId: 'u1', count: 10 },
      { type: 'mfa-verified', userId: 'u1', method: 'totp' },
      { type: 'mfa-verified', userId: 'u1', method: 'recovery-code' },
      ...[1, 2, 3, 4].map((failures) => ({ type: 'mfa-failed', userId: 'u1', method: 'totp', failures, locked: false })),
      { type: 'mfa-failed', userId: 'u1', method: 'totp', failures: 5, locked: true },
      { type: 'mfa-failed', userId: 'u1', method: 'recovery-code', failures: 5, locked: true },
      { type: 'mfa-enabled', userId: 'u1', replaced: true },
      { type: 'mfa-disabled', userId: 'u1' },
    ]);
  });
});

describe('SessionService', () => {
  function setup(options = {}, mfa: { pendingTtl?: Duration } = {}) {
    let clock = 1_000_000;
    const store = new InMemorySessionStore();
    const sessions = new SessionService(storageWith({ sessions: store }), {
      session: { now: () => clock, idleTtl: '1m', absoluteTtl: '5m', touchInterval: '10s', ...options },
      mfa,
    });
    return { sessions, store, tick: (ms: number) => (clock += ms) };
  }

  it('slides the idle timeout on activity but never past the absolute expiry', async () => {
    const { sessions, tick } = setup();
    const { token } = await sessions.create('u1');

    for (let i = 0; i < 5; i++) {
      tick(50_000); // up to 250 s, each within the 60 s idle window
      expect(await sessions.validate(token)).not.toBeNull();
    }

    tick(50_000); // 300 s: idle is fine (50 s), the absolute limit is not
    expect(await sessions.validate(token)).toBeNull();
  });

  it('expires after the idle timeout', async () => {
    const { sessions, tick } = setup();
    const { token } = await sessions.create('u1');
    tick(60_000);
    expect(await sessions.validate(token)).toBeNull();
  });

  it('fails closed on an expiry the store cannot give back (an Invalid Date): the session is over', async () => {
    const { sessions, store } = setup({ idleTtl: 0 }); // nothing but the absolute expiry ends it
    const { token, session } = await sessions.create('u1');
    const read = store.getSession.bind(store);
    vi.spyOn(store, 'getSession').mockImplementation(async (id) => {
      const record = await read(id);
      return record && { ...record, expiresAt: new Date(Number.NaN) }; // a misnamed column, say
    });

    expect(await sessions.validate(token)).toBeNull();
    await expect(read(session.id)).resolves.toBeUndefined(); // deleted, as past its expiry
  });

  it('rotate() replaces the id and keeps the absolute expiry', async () => {
    const { sessions, tick } = setup();
    const first = await sessions.create('u1', { mfa: 'pending' });
    tick(10_000);
    const second = (await sessions.rotate(first.session, { mfa: 'verified' }))!;

    expect(await sessions.validate(first.token)).toBeNull();
    const live = await sessions.validate(second.token);
    expect(live).toMatchObject({ userId: 'u1', mfa: 'verified', expiresAt: first.session.expiresAt });
    expect(second.cookie).toMatch(/Max-Age=290;/);
  });

  it('expires a pending session after mfa.pendingTtl; a verified sign-in lives the absolute lifetime', async () => {
    const { sessions, store, tick } = setup({ idleTtl: '4m' }, { pendingTtl: '30s' });
    const pending = await sessions.create('u1', { mfa: 'pending' });
    const verified = await sessions.create('u1');

    expect(pending.session.expiresAt.getTime()).toBe(pending.session.createdAt.getTime() + 30_000);
    expect(pending.cookie).toMatch(/Max-Age=30;/);
    expect(verified.session.expiresAt.getTime()).toBe(verified.session.createdAt.getTime() + 300_000);

    tick(20_000);
    expect(await sessions.validate(pending.token)).toMatchObject({ mfa: 'pending' });

    tick(15_000); // 35 s: past pendingTtl, well within idle and absolute
    expect(await sessions.validate(pending.token)).toBeNull();
    expect(await store.getSession(pending.session.id)).toBeUndefined(); // gone, like any expired session
    expect(await sessions.validate(verified.token)).toMatchObject({ userId: 'u1' });
  });

  it('activity slides a pending session’s idle timeout, never past mfa.pendingTtl', async () => {
    const { sessions, tick } = setup({ idleTtl: '20s', touchInterval: '1s' }, { pendingTtl: '30s' });
    const { token } = await sessions.create('u1', { mfa: 'pending' });

    tick(15_000);
    expect(await sessions.validate(token)).not.toBeNull(); // touched at 15 s

    tick(14_000);
    expect(await sessions.validate(token)).not.toBeNull(); // 29 s: idle since 15 s, still pending

    tick(2_000);
    expect(await sessions.validate(token)).toBeNull(); // 31 s: the idle window is open, the pending one is not
  });

  it('completing the second factor gives the session the absolute lifetime, counted from the sign-in', async () => {
    const { sessions, tick } = setup({ idleTtl: '4m' }, { pendingTtl: '30s' });
    const pending = await sessions.create('u1', { mfa: 'pending' });

    tick(20_000);
    const done = (await sessions.rotate(pending.session, { mfa: 'verified' }))!;
    expect(done.session.expiresAt.getTime()).toBe(pending.session.createdAt.getTime() + 300_000);
    expect(done.cookie).toMatch(/Max-Age=280;/);

    tick(220_000); // 4 min after the sign-in: a pending session would be long gone
    expect(await sessions.validate(done.token)).toMatchObject({ mfa: 'verified' });

    tick(60_000); // 5 min: the absolute lifetime, from the sign-in, not from the code
    expect(await sessions.validate(done.token)).toBeNull();

    // Rotating for another reason keeps a pending session pending, and short-lived.
    const other = await sessions.create('u2', { mfa: 'pending' });
    const rotated = (await sessions.rotate(other.session))!;
    expect(rotated.session).toMatchObject({ mfa: 'pending', expiresAt: other.session.expiresAt });
  });

  it('caps mfa.pendingTtl at session.absoluteTtl', async () => {
    const { sessions } = setup({}, { pendingTtl: '10m' }); // absoluteTtl is 5 min
    const { session, cookie } = await sessions.create('u1', { mfa: 'pending' });
    expect(session.expiresAt.getTime()).toBe(session.createdAt.getTime() + 300_000);
    expect(cookie).toMatch(/Max-Age=300;/);
  });

  it('lists and revokes all of a user’s sessions', async () => {
    const { sessions } = setup();
    const a = await sessions.create('u1');
    const b = await sessions.create('u1');
    await sessions.create('u2');

    expect((await sessions.list('u1')).map((s) => s.id).sort()).toEqual([a.session.id, b.session.id].sort());

    await sessions.revokeAll('u1');
    expect(await sessions.list('u1')).toEqual([]);
    expect(await sessions.list('u2')).toHaveLength(1);
  });

  it('revoke() only ends a session of the given user', async () => {
    const { sessions } = setup();
    const mine = await sessions.create('u1');

    await expect(sessions.revoke(mine.session.id, { userId: 'u2' })).resolves.toBe(false);
    await expect(sessions.revoke('unknown', { userId: 'u1' })).resolves.toBe(false);
    expect(await sessions.validate(mine.token)).not.toBeNull();

    await expect(sessions.revoke(mine.session.id, { userId: 'u1' })).resolves.toBe(true);
    expect(await sessions.validate(mine.token)).toBeNull();
  });

  it('only reads well-formed tokens, and ignores the cookie on cross-site writes', () => {
    const { sessions } = setup({ cookie: { secure: false } });
    const token = 'A'.repeat(43);

    expect(sessions.tokenFrom({ method: 'GET', headers: { cookie: 'sid=short' } })).toBeUndefined();
    expect(sessions.tokenFrom({ method: 'GET', headers: { cookie: `a=1; sid=${token}` } })).toBe(token);

    const post = (headers: Record<string, string>) => ({ method: 'POST', headers: { cookie: `sid=${token}`, ...headers } });
    expect(sessions.tokenFrom(post({ host: 'api.test', origin: 'https://api.test' }))).toBe(token);
    expect(sessions.tokenFrom(post({ host: 'api.test', origin: 'https://evil.test' }))).toBeUndefined();
    expect(sessions.tokenFrom(post({ 'sec-fetch-site': 'cross-site' }))).toBeUndefined();
    expect(sessions.tokenFrom(post({}))).toBe(token); // no Origin: not a browser
  });

  it('judges cross-origin writes as app.enableCsrfProtection() does', () => {
    const token = 'A'.repeat(43);
    const { sessions } = setup({ cookie: { secure: false }, trustedOrigins: ['https://Shop.Example.com:443'] });
    const post = (headers: Record<string, string>) =>
      sessions.tokenFrom({ method: 'POST', headers: { cookie: `sid=${token}`, ...headers } });

    // HTTP/2 names the host in `:authority`; browsers omit `Host` there.
    expect(post({ ':authority': 'api.test', origin: 'https://api.test' })).toBe(token);

    // The default port and the case of the host do not matter.
    expect(post({ host: 'API.test:443', origin: 'https://api.test' })).toBe(token);

    // Fetch Metadata decides first: a proxy that rewrote `Host` does not make a same-origin request cross-origin.
    expect(post({ host: 'backend:3000', origin: 'https://api.test', 'sec-fetch-site': 'same-origin' })).toBe(token);
    expect(post({ host: 'api.test', origin: 'https://api.test', 'sec-fetch-site': 'same-site' })).toBeUndefined();

    // Trusted origins are added to the request's own, and normalized like the browser's `Origin`.
    expect(post({ host: 'api.test', origin: 'https://shop.example.com', 'sec-fetch-site': 'same-site' })).toBe(token);
    expect(post({ host: 'api.test', origin: 'https://evil.test', 'sec-fetch-site': 'cross-site' })).toBeUndefined();

    // A WebSocket handshake (no method) opens a channel for writes: same rule (cross-site WebSocket hijacking).
    expect(sessions.tokenFrom({ headers: { cookie: `sid=${token}`, host: 'api.test', origin: 'https://evil.test' } })).toBeUndefined();
    expect(sessions.tokenFrom({ headers: { cookie: `sid=${token}`, host: 'api.test', origin: 'https://api.test' } })).toBe(token);

    // So is the GET that upgrades to one, as graphql-ws hands it to resolvers as `req`.
    const upgrade = (origin: string) =>
      sessions.tokenFrom({ method: 'GET', headers: { cookie: `sid=${token}`, host: 'api.test', origin, upgrade: 'WebSocket' } });
    expect(upgrade('https://evil.test')).toBeUndefined();
    expect(upgrade('https://api.test')).toBe(token);
    expect(sessions.tokenFrom({ method: 'GET', headers: { cookie: `sid=${token}`, host: 'api.test', origin: 'https://evil.test' } })).toBe(token);

    expect(() => setup({ trustedOrigins: ['https://shop.example.com/'] })).toThrow(
      'session.trustedOrigins: "https://shop.example.com/" is not an origin. Write it as scheme://host[:port], without a path.',
    );
  });

  it('names the cookie __Host-sid when the browser allows the prefix, so no subdomain can plant one', async () => {
    const secure = setup();
    expect((await secure.sessions.create('u1')).cookie).toMatch(/^__Host-sid=[\w-]{43}; Max-Age=300; Path=\/; HttpOnly; Secure; SameSite=Lax$/);

    const token = 'A'.repeat(43);
    expect(secure.sessions.tokenFrom({ method: 'GET', headers: { cookie: `sid=${token}` } })).toBeUndefined();
    expect(secure.sessions.tokenFrom({ method: 'GET', headers: { cookie: `__Host-sid=${token}` } })).toBe(token);

    // Plain HTTP (`secure: false`), a `domain` or a `path` rule the prefix out.
    for (const cookie of [{ secure: false }, { domain: 'example.com' }, { path: '/api' }]) {
      expect((await setup({ cookie }).sessions.create('u1')).cookie).toMatch(/^sid=/);
    }

    expect((await setup({ cookieName: 'session' }).sessions.create('u1')).cookie).toMatch(/^session=/);
    expect(() => setup({ cookieName: '__Host-session', cookie: { domain: 'example.com' } })).toThrow(
      'session.cookieName: browsers drop a __Host- cookie unless it is Secure, with Path=/ and no Domain.',
    );
  });

  it('refuses SameSite=None without Secure at startup: browsers would drop the cookie and nobody would stay signed in', async () => {
    expect((await setup({ cookie: { sameSite: 'none' } }).sessions.create('u1')).cookie).toMatch(/; Secure; SameSite=None$/);
    expect(() => setup({ cookie: { sameSite: 'none', secure: false } })).toThrow(
      'session.cookie: browsers drop a SameSite=None cookie unless it is Secure.',
    );
  });

  it('a request that touches a session never brings it back once it is revoked or rotated', async () => {
    const { sessions, tick } = setup();
    const signedOut = await sessions.create('u1');
    tick(20_000); // past `touchInterval`: the next validate() writes `lastActiveAt`
    await Promise.all([sessions.validate(signedOut.token), sessions.revokeAll('u1')]);
    expect(await sessions.validate(signedOut.token)).toBeNull();

    const rotated = await sessions.create('u1');
    tick(20_000);
    await Promise.all([sessions.validate(rotated.token), sessions.rotate(rotated.session)]);
    expect(await sessions.validate(rotated.token)).toBeNull();
  });

  it('a rotation that races a revocation leaves no session behind, however the two interleave', async () => {
    // The revocation lands before the new session is written, or between that and the old one's delete.
    for (const when of ['before-issue', 'before-delete'] as const) {
      const { sessions, store } = setup();
      const { session } = await sessions.create('u1');
      const create = store.createSession.bind(store);
      vi.spyOn(store, 'createSession').mockImplementation(async (record) => {
        if (when === 'before-issue') {
          await sessions.revokeAll('u1');
        }
        await create(record);
        if (when === 'before-delete') {
          await sessions.revokeAll('u1');
        }
      });

      await expect(sessions.rotate(session, { mfa: 'verified' })).resolves.toBeNull();
      await expect(store.listUserSessions('u1')).resolves.toEqual([]);
    }
  });

  it('of two rotations of one session, one wins: a session does not fork', async () => {
    const { sessions, store } = setup();
    const { session } = await sessions.create('u1');

    const results = await Promise.all([sessions.rotate(session), sessions.rotate(session), sessions.rotate(session)]);
    const winners = results.filter((issued) => issued !== null);
    expect(winners).toHaveLength(1);
    await expect(store.listUserSessions('u1')).resolves.toEqual([expect.objectContaining({ id: winners[0]!.session.id })]);
  });

  it('refuses a touchInterval at or past idleTtl: active users would be signed out as idle', () => {
    expect(() => setup({ idleTtl: '30s', touchInterval: '1m' })).toThrow(
      'session.touchInterval (60000 ms) must be shorter than session.idleTtl (30000 ms)',
    );
    expect(() => setup({ idleTtl: '1m', touchInterval: '1m' })).toThrow(/must be shorter than session\.idleTtl/);
    expect(() => setup({ idleTtl: 0, touchInterval: '1h' })).not.toThrow(); // no idle timeout
    expect(() => setup({ idleTtl: '30s', touchInterval: '10s' })).not.toThrow();
  });

  it('list() leaves out sessions past their idle timeout', async () => {
    const { sessions, tick } = setup();
    const idle = await sessions.create('u1');
    tick(30_000);
    const active = await sessions.create('u1');
    tick(35_000); // `idle` was last active 65 s ago, `active` 35 s ago

    expect((await sessions.list('u1')).map((s) => s.id)).toEqual([active.session.id]);
    expect(idle.session.id).not.toBe(active.session.id);
  });

  it('checks durations when it is created, not at the first request', () => {
    expect(() => setup({ idleTtl: '3 days' })).toThrow(/Invalid duration "3 days"/);
    expect(() => setup({}, { pendingTtl: '10 minutes' as never })).toThrow(/Invalid duration "10 minutes"/);
  });
});

describe('TokenService', () => {
  function setup(accessToken: object | null = { key: SECRET, ttl: '15m' }) {
    let clock = 0;
    const store = new InMemoryRefreshTokenStore();
    const events = new AuthenticationEvents();
    const seen: AuthenticationEvent[] = [];
    events.events$.subscribe((event) => seen.push(event));

    const service = new TokenService(
      storageWith({ refreshTokens: store }),
      { accessToken: (accessToken ?? undefined) as never, refreshToken: { ttl: 1_000, absoluteTtl: 2_500, now: () => clock } },
      events,
    );

    const record = (refreshToken: string) => store.getRefreshToken(sha256(refreshToken));
    return { service, store, record, seen, tick: (ms: number) => (clock += ms) };
  }

  it('issues an access token and a refresh token; `expiresIn` is the access token lifetime in seconds', async () => {
    const { service } = setup();
    const pair = await service.issue('u1', { claims: { amr: ['pwd'] } });
    expect(pair).toEqual({ accessToken: expect.any(String), refreshToken: expect.stringMatching(/^[\w-]{43}$/), expiresIn: 900 });
    expect(claimsOf(pair.accessToken)).toMatchObject({ sub: 'u1', amr: ['pwd'] });
  });

  it('rotates within a family and caps it at the absolute lifetime', async () => {
    const { service, record, tick } = setup();
    let current = await service.issue('u1');
    const familyId = (await record(current.refreshToken))!.familyId;

    for (let i = 0; i < 2; i++) {
      tick(900);
      current = await service.refresh(current.refreshToken);
      expect((await record(current.refreshToken))!.familyId).toBe(familyId);
    }

    expect((await record(current.refreshToken))!.expiresAt.getTime()).toBe(2_500); // min(ttl, family end)

    tick(700);
    await expect(service.refresh(current.refreshToken)).rejects.toMatchObject({ reason: 'expired' });
  });

  it('a store that fails mid-refresh leaves the token unspent: the client’s retry is a retry, not a theft', async () => {
    const { service, store, seen } = setup();
    const { refreshToken } = await service.issue('u1');

    // Saving the successor fails, or spending the token does: either way nothing was spent.
    vi.spyOn(store, 'saveRefreshToken').mockRejectedValueOnce(new Error('connection reset'));
    await expect(service.refresh(refreshToken)).rejects.toThrow('connection reset');
    vi.spyOn(store, 'markRefreshTokenUsed').mockRejectedValueOnce(new Error('connection reset'));
    await expect(service.refresh(refreshToken)).rejects.toThrow('connection reset');

    const retried = await service.refresh(refreshToken);
    await expect(service.refresh(retried.refreshToken)).resolves.toMatchObject({ refreshToken: expect.any(String) });
    expect(seen.map((event) => event.type)).toEqual(['sign-in']); // no theft reported, nobody signed out
  });

  it('treats a token whose expiry the store cannot give back (an Invalid Date) as expired, and does not spend it', async () => {
    for (const field of ['expiresAt', 'familyExpiresAt'] as const) {
      const { service, store } = setup();
      const { refreshToken } = await service.issue('u1');
      const read = store.getRefreshToken.bind(store);
      vi.spyOn(store, 'getRefreshToken').mockImplementation(async (id) => {
        const found = await read(id);
        return found && { ...found, [field]: new Date(Number.NaN) }; // a misnamed column, say
      });

      await expect(service.refresh(refreshToken)).rejects.toMatchObject({ reason: 'expired' });
      expect((await read(sha256(refreshToken)))!.usedAt).toBeUndefined();
    }
  });

  it('an expired token retried is expired again, not a reuse; a spent token stays a reuse after it expires', async () => {
    const { service, record, seen, tick } = setup();
    const first = await service.issue('u1');
    const second = await service.refresh(first.refreshToken); // `first` is spent
    tick(1_100); // both past their 1 s lifetime, the family alive

    for (let i = 0; i < 2; i++) {
      await expect(service.refresh(second.refreshToken)).rejects.toMatchObject({ reason: 'expired' });
    }

    expect((await record(second.refreshToken))!.usedAt).toBeUndefined(); // never spent: a retry, not theft
    expect(seen.map((e) => e.type)).toEqual(['sign-in']);

    await expect(service.refresh(first.refreshToken)).rejects.toMatchObject({ reason: 'reused' }); // theft signal kept
    expect(seen.map((e) => e.type)).toEqual(['sign-in', 'refresh-token-reused']);
  });

  it('revokes the family when a rotated token is reused, and reports it', async () => {
    const { service, record, seen } = setup();
    const first = await service.issue('u1', { method: 'password' });
    const familyId = (await record(first.refreshToken))!.familyId;
    const second = await service.refresh(first.refreshToken);

    const reuse = await service.refresh(first.refreshToken).catch((error) => error);
    expect(reuse).toBeInstanceOf(RefreshTokenError);
    expect(reuse).toBeInstanceOf(AuthenticationError); // a 401 when a route lets it escape
    expect(reuse).toMatchObject({ reason: 'reused', message: 'Refresh token reused' });

    await expect(service.refresh(second.refreshToken)).rejects.toMatchObject({ reason: 'invalid' });

    expect(seen).toEqual([
      { type: 'sign-in', userId: 'u1', tokenFamilyId: familyId, method: 'password' },
      { type: 'refresh-token-reused', userId: 'u1', tokenFamilyId: familyId },
    ]);
  });

  it('treats a concurrent double-spend as reuse', async () => {
    const { service } = setup();
    const first = await service.issue('u1');

    const results = await Promise.allSettled([service.refresh(first.refreshToken), service.refresh(first.refreshToken)]);
    expect(results.map((r) => r.status).sort()).toEqual(['fulfilled', 'rejected']);

    const winner = results.find((r) => r.status === 'fulfilled') as PromiseFulfilledResult<{ refreshToken: string }>;
    await expect(service.refresh(winner.value.refreshToken)).rejects.toMatchObject({ reason: 'invalid' });
  });

  it('signs every refreshed access token with the sign-in claims', async () => {
    const { service } = setup();
    let current = await service.issue('u1', { claims: { amr: ['pwd', 'sso'], auth_time: 1 } });
    for (let i = 0; i < 3; i++) {
      current = await service.refresh(current.refreshToken);
    }

    expect(claimsOf(current.accessToken)).toMatchObject({ sub: 'u1', amr: ['pwd', 'sso'], auth_time: 1 });

    const plain = await service.refresh((await service.issue('u1')).refreshToken);
    expect(claimsOf(plain.accessToken).amr).toBeUndefined();
  });

  it('owns the amr values that mean a second factor: the app cannot mint verified tokens by accident', async () => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    try {
      const { service } = setup();

      // Without a code: `mfa`, `otp` and `hwk` are dropped, the rest kept and deduplicated.
      const mixed = await service.issue('u1', { claims: { amr: ['pwd', 'mfa', 'otp', 'pwd', 'hwk'], auth_time: 1 } });
      expect(claimsOf(mixed.accessToken)).toMatchObject({ amr: ['pwd'], auth_time: 1 });
      expect(claimsOf((await service.refresh(mixed.refreshToken)).accessToken).amr).toEqual(['pwd']); // the family keeps the cleaned claims

      const only = await service.issue('u1', { claims: { amr: ['mfa'] } });
      expect(claimsOf(only.accessToken)).not.toHaveProperty('amr'); // nothing left: no empty claim

      expect(warn).toHaveBeenCalledTimes(1); // once per process, whatever the number of sign-ins
      expect(warn.mock.calls[0][0]).toBe(
        "issue() dropped 'mfa', 'otp', 'hwk' from `claims.amr`: those values mean a verified second factor, which only the service " +
          'records (`mfa`, once a code was verified). Remove them from the claims passed to issue().',
      );
      expect(warn.mock.contexts[0]).toMatchObject({ context: 'TokenService' });

      // With a verified code: the service adds `mfa` itself, once.
      const verified = new TokenService(
        storageWith(),
        { accessToken: { key: SECRET }, refreshToken: { now: () => 0 } },
        undefined,
        { isEnrolled: async () => true, verifyTotp: async () => true } as unknown as MfaService,
      );
      const pair = await verified.issue('u1', { claims: { amr: ['pwd', 'mfa'] }, secondFactor: { code: '000000' } });
      expect(claimsOf(pair.accessToken).amr).toEqual(['pwd', 'mfa']);

      // What the provider makes of each.
      const bearer = new (class extends JwtBearerProvider<{ id: string }> {
        validate(claims: { sub?: string }) {
          return { id: claims.sub! };
        }
        state(claims: JwtClaims) {
          return this.mfaState(claims);
        }
      })({ key: SECRET });
      expect(bearer.state(claimsOf(mixed.accessToken))).toBeUndefined();
      expect(bearer.state(claimsOf(pair.accessToken))).toBe('verified');
    } finally {
      warn.mockRestore();
    }
  });

  it('revoke(token) signs out that client only', async () => {
    const { service } = setup();
    const phone = await service.issue('u1');
    const tablet = await service.issue('u1');
    const rotated = await service.refresh(phone.refreshToken);

    await expect(service.revoke(phone.refreshToken)).resolves.toBe(true); // a spent token of the family works too
    await expect(service.refresh(rotated.refreshToken)).rejects.toMatchObject({ reason: 'invalid' });
    await expect(service.refresh(tablet.refreshToken)).resolves.toBeDefined();

    await expect(service.revoke('unknown')).resolves.toBe(false);
    await expect(service.revoke('A'.repeat(43))).resolves.toBe(false);
  });

  it('revokeAll() ends every family of a user', async () => {
    const { service } = setup();
    const a = await service.issue('u1');
    const b = await service.issue('u1');

    await service.revokeAll('u1');

    for (const t of [a, b]) {
      await expect(service.refresh(t.refreshToken)).rejects.toMatchObject({ reason: 'invalid' });
    }
  });

  it('asks a user with an authenticator for a second factor, and records it in `amr`', async () => {
    let clock = 1_700_000_000_000;
    const mfaStore = new InMemoryMfaStore();
    const events = new AuthenticationEvents();
    const seen: AuthenticationEvent[] = [];
    events.events$.subscribe((event) => seen.push(event));

    const mfa = new MfaService(storageWith({ mfa: mfaStore }), { mfa: { encryption: false, now: () => clock } }, events);
    const { secret } = await mfa.enroll('u1', 'alice');
    const code = (offset = 0) => hotp(base32Decode(secret), Math.floor(clock / 30_000) + offset);
    await mfa.confirm('u1', code());
    const [recoveryCode] = await mfa.generateRecoveryCodes('u1');

    const service = new TokenService(storageWith(), { accessToken: { key: SECRET } }, events, mfa);
    seen.length = 0;

    // No second factor: no tokens, and nothing counted against the user's lockout.
    const missing = await service.issue('u1', { claims: { amr: ['pwd'] } }).catch((error: unknown) => error);
    expect(missing).toBeInstanceOf(AuthenticationError);
    expect(missing).toMatchObject({ message: 'Second factor required', code: 'mfa_required', status: 401 });
    await expect(mfaStore.countMfaFailures('u1', 60_000, clock)).resolves.toBe(0);

    const valid = new Set([-1, 0, 1].map((offset) => code(offset)));
    const wrong = ['111111', '222222', '333333'].find((guess) => !valid.has(guess))!;
    await expect(service.issue('u1', { secondFactor: { code: wrong } })).rejects.toMatchObject({
      message: 'Invalid code',
      code: 'mfa_required',
    });

    const pair = await service.issue('u1', { claims: { amr: ['pwd'] }, method: 'password', secondFactor: { code: code(1) } });
    expect(claimsOf(pair.accessToken).amr).toEqual(['pwd', 'mfa']);
    expect(claimsOf((await service.refresh(pair.refreshToken)).accessToken).amr).toEqual(['pwd', 'mfa']);
    expect(seen.filter((event) => event.type === 'sign-in')).toEqual([
      { type: 'sign-in', userId: 'u1', tokenFamilyId: expect.any(String), method: 'password', mfa: 'verified' },
    ]);

    const recovered = await service.issue('u1', { secondFactor: { recoveryCode } });
    expect(claimsOf(recovered.accessToken).amr).toEqual(['mfa']);

    // Users without an authenticator are never asked.
    expect(claimsOf((await service.issue('u2', { secondFactor: { code: '123456' } })).accessToken).amr).toBeUndefined();
  });

  it('refuses to issue without `accessToken`, before spending anything', async () => {
    const { service } = setup(null);
    await expect(service.issue('u1')).rejects.toThrow(/configure `accessToken`/);
    await expect(service.refresh('A'.repeat(43))).rejects.toThrow(/configure `accessToken`/);
    await expect(service.revoke('A'.repeat(43))).rejects.toThrow(/configure `accessToken`/);
    // No refresh tokens without `accessToken`: a sign-out everywhere has none to revoke, and reads no store.
    const unread = {
      get refreshTokens(): never {
        throw new Error('the refresh-token store was read');
      },
    };
    await expect(new TokenService(unread as never).revokeAll('u1')).resolves.toBeUndefined();
  });

  it('checks the signing key when it is created', () => {
    expect(() => setup({ key: 'too short for HS256' })).toThrow(/HS256/);
  });
});

describe('MagicLinkService', () => {
  function setup(now = () => 0, magicLink: Partial<MagicLinkOptions> = {}) {
    const sent: string[] = [];
    const handler = new (class extends MagicLinkHandler {
      send(link: { url: string }) {
        sent.push(link.url);
      }
      resolveUser(email: string) {
        return { id: 'u1', email };
      }
    })();

    const events = new AuthenticationEvents();
    const seen: AuthenticationEvent[] = [];
    events.events$.subscribe((event) => seen.push(event));

    const sessions = new SessionService(storageWith(), {});
    const tokens = new TokenService(storageWith(), {});
    const signIn = new SignInService(sessions, new MfaService(storageWith(), {}), tokens, undefined, undefined, events);

    const options = { magicLink: { url: 'https://app.test/magic', ttl: '1s' as const, now, ...magicLink } };
    const service = new MagicLinkService(
      storageWith(),
      registryWith(options, { magicLink: handler }),
      signIn,
      options,
      undefined,
      undefined,
      events,
    );

    const tokenOf = (url: string) => new URL(url).searchParams.get('token')!;
    /** Outside HTTP: the request of the browser that holds `cookie` (a `Set-Cookie` value). */
    const browser = (cookie: string | undefined) => ({ request: { headers: { ...(cookie && { cookie: cookie.split(';')[0] }) } } });
    return { service, sent, seen, tokenOf, browser };
  }

  it('expires links', async () => {
    let clock = 0;
    const { service, sent, seen, tokenOf, browser } = setup(() => clock);
    const first = await service.create('a@b.c');
    const second = await service.create('a@b.c');
    const [firstToken, secondToken] = sent.map(tokenOf);

    await expect(service.consume(firstToken, browser(first.cookie))).resolves.toMatchObject({ session: { userId: 'u1' } });

    clock = 1_000;
    await expect(service.consume(secondToken, browser(second.cookie))).resolves.toBeNull();
    await expect(service.consume('../../etc', browser(second.cookie))).resolves.toBeNull();

    expect(seen.filter((e) => e.type === 'magic-link-refused')).toEqual([
      { type: 'magic-link-refused', reason: 'expired', email: 'a@b.c' },
      { type: 'magic-link-refused', reason: 'unknown' },
    ]);
  });

  it('signs in through SignInService, outside HTTP too: the cookies are returned', async () => {
    const { service, sent, seen, tokenOf, browser } = setup();
    const created = await service.create('a@b.c');
    expect(created.cookie).toMatch(/^__Host-magic_link_tx=[\w-]{12}\.[\w-]{43}; Max-Age=1; Path=\/; HttpOnly; Secure; SameSite=Lax$/);

    const result = await service.consume(tokenOf(sent[0]), browser(created.cookie));
    expect(result!.cookie).toMatch(/^__Host-sid=[\w-]{43}; /);
    expect(seen).toEqual([{ type: 'sign-in', userId: 'u1', sessionId: result!.session.id, method: 'magic-link' }]);
  });

  it('binds a link to the browser that requested it (login CSRF), and keeps it for that browser', async () => {
    const { service, sent, seen, tokenOf, browser } = setup();
    const mine = await service.create('a@b.c');
    const theirs = await service.create('attacker@b.c');
    const [myToken, theirToken] = sent.map(tokenOf);

    // The attacker's link, opened in a browser without their cookie, or with a cookie of its own:
    // the one refusal told apart from a bad link, since nothing was looked up to decide it.
    await expect(service.consume(theirToken, browser(undefined))).rejects.toThrow(MagicLinkError);
    await expect(service.consume(theirToken, browser(mine.cookie))).rejects.toMatchObject({
      name: 'MagicLinkError',
      reason: 'not-this-browser',
      status: 401,
      code: 'not_this_browser',
      message: 'Open the link in the browser you requested it from, or request a new one here',
    });

    expect(seen).toEqual([
      { type: 'magic-link-refused', reason: 'not-this-browser' },
      { type: 'magic-link-refused', reason: 'not-this-browser' },
    ]);

    // Neither attempt burned it, or my cookie: each link still works where it was requested.
    await expect(service.consume(theirToken, browser(theirs.cookie))).resolves.toMatchObject({ session: { userId: 'u1' } });
    await expect(service.consume(myToken, browser(mine.cookie))).resolves.toMatchObject({ session: { userId: 'u1' } });
  });

  it('bindToBrowser: false sets no cookie and asks for none', async () => {
    const { service, sent, tokenOf, browser } = setup(undefined, { bindToBrowser: false });
    const created = await service.create('a@b.c');
    expect(created).toEqual({ expiresAt: expect.any(Date) });
    await expect(service.consume(tokenOf(sent[0]), browser(undefined))).resolves.toMatchObject({ session: { userId: 'u1' } });
  });

  it('names the cookie magic_link_tx when its attributes rule the __Host- prefix out', async () => {
    const { service } = setup(undefined, { cookie: { secure: false, sameSite: 'strict' } });
    const created = await service.create('a@b.c');
    expect(created.cookie).toMatch(/^magic_link_tx=[\w-]{12}\.[\w-]{43}; Max-Age=1; Path=\/; HttpOnly; SameSite=Lax$/); // always Lax
  });

  it('names the missing url at startup, and says how to enable the feature when it is off', async () => {
    const signIn = {} as SignInService;
    expect(() => new MagicLinkService(storageWith(), registryWith(), signIn, { magicLink: {} as never })).toThrow(
      /`magicLink.url` is required/,
    );

    const off = new MagicLinkService(storageWith(), registryWith(), signIn, {});
    await expect(off.create('a@b.c')).rejects.toThrow(
      'MagicLinkService: magic links are not enabled. Configure `magicLink` in the AuthenticationModule options, and ' +
        "register a MagicLinkHandler: `registry.registerHandler('magicLink', this)`.",
    );
  });
});

describe('in-memory stores stay bounded', () => {
  it('forget expired sessions and refresh-token families as new ones are written', async () => {
    let clock = 0;
    const sessionStore = new InMemorySessionStore();
    const sessions = new SessionService(storageWith({ sessions: sessionStore }), { session: { now: () => clock, absoluteTtl: '1m', idleTtl: 0 } });
    const tokenStore = new InMemoryRefreshTokenStore();
    const tokens = new TokenService(storageWith({ refreshTokens: tokenStore }), { accessToken: { key: SECRET }, refreshToken: { absoluteTtl: '1m', now: () => clock } });

    for (let i = 0; i < 3_000; i++) {
      await sessions.create(`u${i}`);
      await tokens.issue(`u${i}`);
      clock += 1_000;
    }

    const live = await sessions.create('last');
    expect((sessionStore as unknown as { sessions: Map<string, unknown> }).sessions.size).toBeLessThanOrEqual(1_024);
    expect((tokenStore as unknown as { tokens: Map<string, unknown> }).tokens.size).toBeLessThanOrEqual(1_024);
    expect(await sessions.validate(live.token)).not.toBeNull(); // live ones stay
  });

  it('cap pending OIDC logins and magic links, dropping the oldest', async () => {
    const logins = new InMemoryOidcStateStore();
    const links = new InMemoryMagicLinkStore();
    const expiresAt = new Date(Date.now() + 600_000);

    for (let i = 0; i < 10_005; i++) {
      await logins.saveOidcState({ state: `s${i}`, provider: 'google', codeVerifier: 'v', createdAt: new Date(), expiresAt });
      await links.saveMagicLink({ id: `l${i}`, email: 'a@b.c', createdAt: new Date(), expiresAt });
    }

    await expect(logins.consumeOidcState('s4')).resolves.toBeUndefined();
    await expect(logins.consumeOidcState('s5')).resolves.toMatchObject({ state: 's5' });

    await expect(links.consumeMagicLink('l4')).resolves.toBeUndefined();
    await expect(links.consumeMagicLink('l10004')).resolves.toMatchObject({ id: 'l10004' });
  });

  it('cap email tokens, dropping the ones that expire first: reset links never push out a verification link', async () => {
    const tokens = new InMemoryEmailTokenStore();
    const now = Date.now();
    const token = (id: string, purpose: 'password-reset' | 'email-verification', ttl: number) => ({
      id,
      purpose,
      userId: 'u1',
      email: 'a@b.c',
      createdAt: new Date(now),
      expiresAt: new Date(now + ttl),
    });

    await tokens.saveEmailToken(token('verify', 'email-verification', 86_400_000));
    for (let i = 0; i < 10_000; i++) {
      await tokens.saveEmailToken(token(`reset${i}`, 'password-reset', 3_600_000 + i));
    }

    await expect(tokens.consumeEmailToken('verify', 'email-verification')).resolves.toMatchObject({ id: 'verify' });
    await expect(tokens.consumeEmailToken('reset0', 'password-reset')).resolves.toBeUndefined(); // expired first
    await expect(tokens.consumeEmailToken('reset1', 'password-reset')).resolves.toMatchObject({ id: 'reset1' });
  });
});

describe('helpers', () => {
  it('safeRedirectPath only allows same-origin paths', () => {
    expect(safeRedirectPath('/a?b=1')).toBe('/a?b=1');
    expect(safeRedirectPath('/k%C5%82os?q=a%20b#top')).toBe('/k%C5%82os?q=a%20b#top');

    // Only what a Location header can carry: Fastify answers 500 to a raw U+2028, and a space is not a URL character.
    for (const bad of ['/a\u2028b', '/książki', '/a b']) {
      expect(safeRedirectPath(bad)).toBeUndefined();
    }

    for (const bad of ['//evil.test', '/\\evil.test', 'https://evil.test', 'javascript:alert(1)', '/a\nb', '/ab', undefined, 42]) {
      expect(safeRedirectPath(bad)).toBeUndefined();
    }
  });

  it('safeRedirectPath keeps at most 2,048 characters: logins and links store it, and anyone can start one', () => {
    expect(safeRedirectPath(`/${'a'.repeat(2_047)}`)).toHaveLength(2_048);
    expect(safeRedirectPath(`/${'a'.repeat(2_048)}`)).toBeUndefined();
  });

  it('readCookie parses the raw header', () => {
    expect(readCookie('a=1; sid=abc%3D; b=2', 'sid')).toBe('abc=');
    expect(readCookie('sid="quoted"', 'sid')).toBe('quoted');
    expect(readCookie('xsid=1; sid=2', 'sid')).toBe('2');
    expect(readCookie('sid=first; sid=second', 'sid')).toBe('first');
    expect(readCookie(' \tsid=spaced \t', 'sid')).toBe('spaced');
    expect(readCookie(undefined, 'sid')).toBeUndefined();
  });

  it('readCookie strips only spaces and tabs, so a planted `\\xA0__Host-sid` is not `__Host-sid`', () => {
    // A sibling subdomain may set `\xA0__Host-sid` with its own Domain and Path: browsers see no
    // prefix on that name, store it, and send it first for the longer path. Node reads the byte as U+00A0.
    for (const pad of [' ', '﻿', ' ']) {
      expect(readCookie(`${pad}__Host-sid=planted; __Host-sid=genuine`, '__Host-sid')).toBe('genuine');
      expect(readCookie(`${pad}__Host-sid=planted`, '__Host-sid')).toBeUndefined();
    }
  });

  it('toMs refuses durations over 100 years, which would put every expiry past the range of Date', () => {
    expect(toMs('36525d')).toBe(3_155_760_000_000); // 100 years, the most
    for (const huge of [Number.MAX_SAFE_INTEGER, '100000000w', '36526d', 3_155_760_000_001] as never[]) {
      expect(() => toMs(huge)).toThrow(/longer than 100 years/);
    }
  });

  it('toMs reads milliseconds and unit strings, and rejects the rest', () => {
    expect([toMs(250), toMs('30s'), toMs('15m'), toMs('3d'), toMs('1.5h')]).toEqual([250, 30_000, 900_000, 259_200_000, 5_400_000]);
    for (const bad of [-1, Number.NaN, '3 days', '15', 'm'] as never[]) {
      expect(() => toMs(bad)).toThrow(TypeError);
    }
  });
});

describe('AuthenticationContext next to another AsyncLocalStorage (e.g. NestJS Observe)', () => {
  it('keeps both stores independent in either nesting order', async () => {
    const trace = new AsyncLocalStorage<{ traceId: string }>();
    const auth = new AuthenticationContext<{ id: string }>();

    const seen = await trace.run({ traceId: 't1' }, () =>
      auth.run({ user: { id: 'u1' } }, async () => {
        await sleep(1);
        const inner = await trace.run({ traceId: 't2' }, async () => {
          await sleep(1);
          return [trace.getStore()?.traceId, auth.user?.id];
        });
        return [...inner, trace.getStore()?.traceId, auth.user?.id];
      }),
    );

    expect(seen).toEqual(['t2', 'u1', 't1', 'u1']);
    expect(auth.user).toBeNull();
  });
});

describe('AuthenticationGuard brand', () => {
  const brand = Symbol.for('@nestjs/authentication:guard');

  it('is a static registry-symbol property, inherited by subclasses whatever their names', () => {
    class Gatekeeper extends AuthenticationGuard {}
    expect((AuthenticationGuard as unknown as Record<symbol, unknown>)[brand]).toBe(true);
    expect((Gatekeeper as unknown as Record<symbol, unknown>)[brand]).toBe(true);

    // What @nestjs/authorization checks, on an APP_GUARD instance.
    const instance = new Gatekeeper(new Reflector(), new HttpAdapterHost(), undefined as never);
    expect((instance.constructor as unknown as Record<symbol, unknown>)[brand]).toBe(true);
  });

  it('is not exported: nothing to import, the symbol is global', async () => {
    const exported = await import('../lib/index.js');
    expect(Object.values(exported)).not.toContain(brand);
  });
});

describe('AuthenticationGuard, outside HTTP', () => {
  class TokenInPayload extends AuthenticationProvider<{ id: string }> {
    authenticate(context: ExecutionContext): AuthenticationResult<{ id: string }> | null {
      const data = context.switchToRpc().getData();
      if (data?.token === 't') {
        return { user: { id: 'svc' } };
      }
      if (data?.token === 'mfa') {
        return { user: { id: 'svc' }, mfa: 'verified' };
      }
      return null;
    }
  }

  async function guardWith(provider: AuthenticationProvider<any, any>) {
    const registry = new AuthenticationRegistry();
    registry.registerProvider(provider);
    return new AuthenticationGuard(new Reflector(), new HttpAdapterHost(), registry);
  }

  const call = (handler: { prototype: object } & (new () => object), method: string, data: object, rpcContext: object = {}) => {
    const ctx = new ExecutionContextHost([data, rpcContext], handler as never, (handler.prototype as never)[method]);
    ctx.setType('rpc');
    return ctx;
  };

  it('answers anonymous calls with an RpcException and records users on the transport context', async () => {
    const { RpcException } = await import('@nestjs/microservices');
    const guard = await guardWith(new TokenInPayload());
    class Handler {
      handle() {}
    }

    const error = await guard.canActivate(call(Handler, 'handle', {})).catch((e) => e);
    expect(error).toBeInstanceOf(RpcException);
    expect(error.getError()).toEqual({ statusCode: 401, message: 'Unauthorized', errorCode: 'missing_credentials' });

    const rpcContext: { user?: unknown } = {};
    await expect(guard.canActivate(call(Handler, 'handle', { token: 't' }, rpcContext))).resolves.toBe(true);
    expect(rpcContext.user).toEqual({ id: 'svc' });
  });

  it('merges method options over class options, field by field', async () => {
    const guard = await guardWith(new TokenInPayload());
    @Authenticate({ optional: true })
    class Optional {
      @Authenticate({ mfa: true })
      stepUp() {}
      plain() {}
    }
    @Public()
    class Open {
      @Authenticate()
      strict() {}
    }

    // optional (class) + mfa (method): anonymous passes, a user without MFA does not.
    await expect(guard.canActivate(call(Optional, 'stepUp', {}))).resolves.toBe(true);
    await expect(guard.canActivate(call(Optional, 'stepUp', { token: 't' }))).rejects.toMatchObject({
      error: { statusCode: 401, error: 'mfa_required', errorCode: 'mfa_required', message: 'Second factor required' },
    });
    await expect(guard.canActivate(call(Optional, 'stepUp', { token: 'mfa' }))).resolves.toBe(true);
    await expect(guard.canActivate(call(Optional, 'plain', { token: 't' }))).resolves.toBe(true);

    // @Public() class, @Authenticate() method: required again.
    await expect(guard.canActivate(call(Open, 'strict', {}))).rejects.toMatchObject({ error: { statusCode: 401 } });
  });
});

describe('AuthenticationError thrown under a handler', () => {
  const intercept = async (type: string): Promise<any> => {
    const scope = new AuthenticationScope();
    const interceptor = new AuthenticationScopeInterceptor(scope, new HttpAdapterHost());
    class Handler {
      handle() {}
    }

    const ctx = new ExecutionContextHost([{}, {}], Handler, Handler.prototype.handle);
    ctx.setType(type as never);
    const observable = interceptor.intercept(ctx, { handle: () => throwError(() => new AuthenticationError('Refresh token reused')) });
    return lastValueFrom(observable).catch((error: any) => error);
  };

  it('becomes each transport’s 401', async () => {
    const { RpcException } = await import('@nestjs/microservices');
    const { WsException } = await import('@nestjs/websockets');

    const rpc = await intercept('rpc');
    expect(rpc).toBeInstanceOf(RpcException);
    expect(rpc.getError()).toEqual({ statusCode: 401, message: 'Refresh token reused' });

    const ws = await intercept('ws');
    expect(ws).toBeInstanceOf(WsException);
    expect(ws.getError()).toEqual({ status: 'error', statusCode: 401, message: 'Refresh token reused' });

    // HTTP and GraphQL: Nest's own exception, so Nest's own body.
    for (const type of ['graphql', 'http']) {
      const error = await intercept(type);
      expect(error).toBeInstanceOf(UnauthorizedException);
      expect(error.getResponse()).toEqual(new UnauthorizedException('Refresh token reused').getResponse());
      expect(error.cause).toBeInstanceOf(AuthenticationError); // for logs
    }

    expect(rpc.cause).toBeInstanceOf(AuthenticationError);
  });

  it('the default message gives the body of a bare UnauthorizedException', async () => {
    const scope = new AuthenticationScope();
    const interceptor = new AuthenticationScopeInterceptor(scope, new HttpAdapterHost());
    class Handler {
      handle() {}
    }
    const ctx = new ExecutionContextHost([{}, {}], Handler, Handler.prototype.handle);
    ctx.setType('http');

    // What `AuthenticationContext.requireUser()` throws for an anonymous caller.
    const observable = interceptor.intercept(ctx, { handle: () => throwError(() => new AuthenticationError()) });
    const error = (await lastValueFrom(observable).catch((caught) => caught)) as UnauthorizedException;

    expect(JSON.stringify(error.getResponse())).toBe(JSON.stringify(new UnauthorizedException().getResponse()));
    expect(error.getResponse()).toEqual({ message: 'Unauthorized', statusCode: 401 });
  });

  it('carries a 4xx `status`, so other packages see a caller fault, not an outage', async () => {
    expect(new AuthenticationError()).toMatchObject({ status: 401, name: 'AuthenticationError' });
    expect(new RefreshTokenError('reused')).toMatchObject({ status: 401 });
    expect(new JwtError('token expired')).toMatchObject({ status: 401, name: 'JwtError' });
    expect(new MagicLinkError()).toMatchObject({ status: 401, name: 'MagicLinkError', code: 'not_this_browser' });

    const conflict = new MfaAlreadyEnrolledError('u1');
    expect(conflict).toMatchObject({ status: 409, userId: 'u1', message: 'Authenticator already enrolled' });

    // One base class for every error of the package an app may catch.
    for (const error of [new RefreshTokenError('reused'), new JwtError('x'), new MagicLinkError(), conflict]) {
      expect(error).toBeInstanceOf(AuthenticationError);
    }
  });

  it('a 409 becomes each transport’s conflict, and `code` becomes the body’s `errorCode` (and `error`)', async () => {
    const scope = new AuthenticationScope();
    const interceptor = new AuthenticationScopeInterceptor(scope, new HttpAdapterHost());
    class Handler {
      handle() {}
    }

    const run = async (type: string, error: Error): Promise<any> => {
      const ctx = new ExecutionContextHost([{}, {}], Handler, Handler.prototype.handle);
      ctx.setType(type as never);
      return lastValueFrom(interceptor.intercept(ctx, { handle: () => throwError(() => error) })).catch((e: unknown) => e);
    };

    const http = await run('http', new MfaAlreadyEnrolledError('u1'));
    expect(http.getStatus()).toBe(409);
    expect(http.getResponse()).toEqual({ message: 'Authenticator already enrolled', error: 'Conflict', statusCode: 409 });

    const ws = await run('ws', new MfaAlreadyEnrolledError('u1'));
    expect(ws.getError()).toEqual({ status: 'error', statusCode: 409, message: 'Authenticator already enrolled' });

    const coded = await run('http', new AuthenticationError('Second factor required', { code: 'mfa_required' }));
    expect(coded.getResponse()).toEqual({ message: 'Second factor required', error: 'mfa_required', statusCode: 401, errorCode: 'mfa_required' });
    expect(coded.errorCode).toBe('mfa_required');
  });

  describe('`errorCode` and `details` in the body, on every transport', () => {
    const run = async (type: string, error: Error): Promise<any> => {
      const interceptor = new AuthenticationScopeInterceptor(new AuthenticationScope(), new HttpAdapterHost());
      class Handler {
        handle() {}
      }
      const ctx = new ExecutionContextHost([{}, {}], Handler, Handler.prototype.handle);
      ctx.setType(type as never);
      return lastValueFrom(interceptor.intercept(ctx, { handle: () => throwError(() => error) })).catch((e: unknown) => e);
    };
    const body = (exception: any) => ('getResponse' in exception ? exception.getResponse() : exception.getError());
    const throttled = () =>
      new AuthenticationError('Too many attempts', {
        code: 'too_many_attempts',
        details: { retryAfter: 30 },
        challenge: 'Bearer realm="app"',
        cause: new Error('internal: limiter key ip:10.0.0.1'),
      });

    it('HTTP and GraphQL: Nest’s own body and `errorCode` for the code, key for key, then `details`', async () => {
      // `error` as before (the code as Nest's description), then Nest's own `errorCode`.
      const nest = new UnauthorizedException('Too many attempts', { description: 'too_many_attempts', errorCode: 'too_many_attempts' });
      expect(JSON.stringify(nest.getResponse())).toBe(
        '{"message":"Too many attempts","error":"too_many_attempts","statusCode":401,"errorCode":"too_many_attempts"}',
      );
      for (const type of ['http', 'graphql']) {
        const error = await run(type, throttled());
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(JSON.stringify(error.getResponse())).toBe(JSON.stringify({ ...(nest.getResponse() as object), details: { retryAfter: 30 } }));
        expect(error.errorCode).toBe('too_many_attempts'); // what exception filters read
        expect(error.message).toBe('Too many attempts');
        expect(error.cause).toBeInstanceOf(AuthenticationError);
      }
    });

    it('ws and rpc: the same keys in their payloads', async () => {
      const fields = { statusCode: 401, error: 'too_many_attempts', message: 'Too many attempts', errorCode: 'too_many_attempts', details: { retryAfter: 30 } };
      expect((await run('ws', throttled())).getError()).toEqual({ status: 'error', ...fields });
      expect((await run('rpc', throttled())).getError()).toEqual(fields);
    });

    it('sends `details` without a code, and no `errorCode` where there is none', async () => {
      const error = () => new AuthenticationError('Slow down', { details: { retryAfter: 5 } });
      const http = await run('http', error());
      expect(http.getResponse()).toEqual({ message: 'Slow down', error: 'Unauthorized', statusCode: 401, details: { retryAfter: 5 } });
      expect(http.errorCode).toBeUndefined();
      expect((await run('ws', error())).getError()).toEqual({ status: 'error', statusCode: 401, message: 'Slow down', details: { retryAfter: 5 } });
      expect((await run('rpc', error())).getError()).toEqual({ statusCode: 401, message: 'Slow down', details: { retryAfter: 5 } });
    });

    it('leaves code-less refusals as they were: `Unauthorized` or `Conflict` in `error` over HTTP, none elsewhere', async () => {
      for (const type of ['http', 'graphql']) {
        expect((await run(type, new RefreshTokenError('reused'))).getResponse()).toEqual({
          message: 'Refresh token reused',
          error: 'Unauthorized',
          statusCode: 401,
        });
        expect((await run(type, new MfaAlreadyEnrolledError('u1'))).getResponse()).toEqual({
          message: 'Authenticator already enrolled',
          error: 'Conflict',
          statusCode: 409,
        });
        expect((await run(type, new AuthenticationError())).getResponse()).toEqual({ message: 'Unauthorized', statusCode: 401 });
      }
      for (const type of ['ws', 'rpc']) {
        for (const error of [new RefreshTokenError('reused'), new MfaAlreadyEnrolledError('u1'), new AuthenticationError()]) {
          const payload = body(await run(type, error));
          expect(payload).not.toHaveProperty('errorCode');
          expect(payload).not.toHaveProperty('error');
          expect(payload).not.toHaveProperty('details');
        }
      }
    });

    it('never puts the cause, the challenge or other properties of the error in the body', async () => {
      for (const type of ['http', 'graphql', 'ws', 'rpc']) {
        const payload = JSON.stringify(body(await run(type, throttled())));
        expect(payload).not.toMatch(/internal|limiter|realm|cause|challenge|stack/);
      }
    });
  });

  it('other errors pass through untouched', async () => {
    const scope = new AuthenticationScope();
    const interceptor = new AuthenticationScopeInterceptor(scope, new HttpAdapterHost());
    class Handler {
      handle() {}
    }
    const ctx = new ExecutionContextHost([{}, {}], Handler, Handler.prototype.handle);

    const failure = new Error('store down');
    const error = await lastValueFrom(interceptor.intercept(ctx, { handle: () => throwError(() => failure) })).catch((e) => e);
    expect(error).toBe(failure);
  });
});

describe('TOTP secret encryption at rest', () => {
  const K1 = 'first-key-that-is-at-least-32-characters';
  const K2 = Buffer.alloc(32, 7);
  const clock = 1_700_000_000_000;
  const service = (store: InMemoryMfaStore, encryption: ConstructorParameters<typeof MfaService>[1]) =>
    new MfaService(storageWith({ mfa: store }), encryption);
  const withKeys = (store: InMemoryMfaStore, ...keys: (string | Buffer)[]) =>
    service(store, { mfa: { now: () => clock, encryption: { keys } } });
  const code = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(clock / 30_000) + offset);
  /** The id a key writes into its ciphertexts (the second part). */
  const idOf = (key: string | Buffer) => new SecretCipher({ keys: [key] }).encrypt('probe', 'probe').split('.')[1];

  let logged: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => logged.mockRestore());

  async function enrolled(mfa: MfaService, userId = 'u1') {
    const { secret } = await mfa.enroll(userId, userId);
    expect(await mfa.confirm(userId, code(secret, -1))).toBe(true);
    return secret;
  }

  it('stores ciphertext, never the base32 secret, and still verifies', async () => {
    const store = new InMemoryMfaStore();
    const mfa = withKeys(store, K1);
    const secret = await enrolled(mfa);

    const stored = (await store.getTotp('u1'))!.secret;
    expect(stored.split('.')).toEqual(['v1', idOf(K1), expect.stringMatching(/^[\w-]{16}$/), expect.any(String), expect.stringMatching(/^[\w-]{22}$/)]);
    expect(stored).not.toContain(secret);
    await expect(mfa.verifyTotp('u1', code(secret))).resolves.toBe(true);

    // Fresh IV each time: the same secret never encrypts to the same value.
    const cipher = new SecretCipher({ keys: [K1] });
    expect(cipher.encrypt(secret, 'totp.u1')).not.toBe(cipher.encrypt(secret, 'totp.u1'));
  });

  it('derives key ids from the keys: stable, distinct, and not the key material', () => {
    expect(idOf(K1)).toMatch(/^[\w-]{8}$/);
    expect(idOf(K1)).toBe(idOf(K1));
    expect(idOf(K2)).toMatch(/^[\w-]{8}$/);
    expect(idOf(K1)).not.toBe(idOf(K2));
    expect(K1).not.toContain(idOf(K1));
    expect(K2.toString('base64url')).not.toContain(idOf(K2));

    // A key listed twice is one key.
    const twice = new SecretCipher({ keys: [K1, K1] });
    expect(twice.decrypt(new SecretCipher({ keys: [K1] }).encrypt('s', 'c'), 'c').plaintext).toBe('s');
  });

  it('rotates: old keys still decrypt, and a successful verify re-encrypts with the new key', async () => {
    const store = new InMemoryMfaStore();
    const secret = await enrolled(withKeys(store, K1));
    const rotated = withKeys(store, K2, K1);

    await expect(rotated.verifyTotp('u1', code(secret))).resolves.toBe(true);
    expect((await store.getTotp('u1'))!.secret.startsWith(`v1.${idOf(K2)}.`)).toBe(true);
    expect((await store.getTotp('u1'))!.lastUsedStep).toBe(Math.floor(clock / 30_000)); // step claim kept

    // K1 can now be retired for this user.
    await expect(withKeys(store, K2).verifyTotp('u1', code(secret, 1))).resolves.toBe(true);
  });

  it('reencrypt() rewrites idle users for a rotation job', async () => {
    const store = new InMemoryMfaStore();
    const secret = await enrolled(withKeys(store, K1), 'idle');
    const rotated = withKeys(store, K2, K1);

    await expect(rotated.reencrypt('idle')).resolves.toBe(true);
    await expect(rotated.reencrypt('idle')).resolves.toBe(false);

    await expect(withKeys(store, K2).verifyTotp('idle', code(secret))).resolves.toBe(true);
  });

  it('fails closed on tampered values, rows copied between users, rewritten headers and unknown keys', async () => {
    const store = new InMemoryMfaStore();
    const mfa = withKeys(store, K1, K2);
    const aliceSecret = await enrolled(mfa, 'alice');
    await enrolled(mfa, 'mallory');
    const alice = (await store.getTotp('alice'))!;

    // Mallory's row now holds Alice's ciphertext: AAD binds it to 'alice'.
    await store.saveTotp('mallory', { ...alice, lastUsedStep: undefined });
    await expect(mfa.verifyTotp('mallory', code(aliceSecret))).resolves.toBe(false);

    const parts = alice.secret.split('.');
    const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
    for (const tampered of [
      [parts[0], parts[1], parts[2], flip(parts[3]), parts[4]].join('.'), // ciphertext
      [parts[0], parts[1], parts[2], parts[3], flip(parts[4])].join('.'), // tag
      [parts[0], idOf(K2), parts[2], parts[3], parts[4]].join('.'), // header says another key
      [parts[0], 'gone', parts[2], parts[3], parts[4]].join('.'), // unknown key id
      `v1.${idOf(K1)}.x.y`, // malformed
      aliceSecret, // plaintext planted in the store
    ]) {
      await store.saveTotp('alice', { ...alice, secret: tampered, lastUsedStep: undefined });
      await expect(mfa.verifyTotp('alice', code(aliceSecret, 1))).resolves.toBe(false);
    }

    await expect(store.countMfaFailures('alice', 60_000, Date.now())).resolves.toBe(0); // integrity failures are not the user's
    expect(logged).toHaveBeenCalledWith(expect.stringContaining('TOTP secret of user alice could not be decrypted'));
  });

  it('requires a key once MFA is configured; `false` opts out explicitly', async () => {
    const store = new InMemoryMfaStore();
    expect(() => service(store, { mfa: {} as never })).toThrow(/mfa.encryption` is required/);

    const plaintext = service(store, { mfa: { now: () => clock, encryption: false } });
    const secret = await enrolled(plaintext);
    expect((await store.getTotp('u1'))!.secret).toBe(secret);

    // Without any MFA config, enrollment refuses rather than storing plaintext.
    await expect(service(store, {}).enroll('u2', 'u2')).rejects.toThrow(/not configured/);
    // And MFA is off: an enrolled user has no second factor to give, and the store is not read.
    const getTotp = vi.spyOn(store, 'getTotp');
    await expect(service(store, {}).isEnrolled('u1')).resolves.toBe(false);
    expect(getTotp).not.toHaveBeenCalled();
  });

  it('without the `mfa` option, every method but isEnrolled() throws before touching the store', async () => {
    const store = new InMemoryMfaStore();
    const touched = vi.fn();
    const watched = new Proxy(store, {
      get: (target, key) => {
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? (...args: unknown[]) => (touched(key), value.apply(target, args)) : value;
      },
    });
    const off = service(watched, {});

    await expect(off.isEnrolled('u1')).resolves.toBe(false);
    for (const call of [
      () => off.enroll('u1', 'u1'),
      () => off.confirm('u1', '000000'),
      () => off.verifyTotp('u1', '000000'),
      () => off.verifyRecoveryCode('u1', 'AAAAA-AAAAA'),
      () => off.generateRecoveryCodes('u1'),
      () => off.remainingRecoveryCodes('u1'),
      () => off.disable('u1'),
      () => off.reencrypt('u1'),
    ]) {
      await expect(call()).rejects.toThrow('MFA is not configured');
    }
    expect(touched).not.toHaveBeenCalled();
  });

  it('validates keys, naming the offending entry and never its value', () => {
    expect(() => new SecretCipher({ keys: [] })).toThrow('`mfa.encryption.keys` must list at least one key');

    expect(() => new SecretCipher({ keys: [K1, 'too short'] })).toThrow(
      '`mfa.encryption.keys[1]` must be 32 random bytes, or a random string of at least 32 characters',
    );
    expect(() => new SecretCipher({ keys: [Buffer.alloc(31)] })).toThrow(
      '`mfa.encryption.keys[0]` is a Buffer of 31 bytes; it must be 32 bytes.',
    );

    // An unset environment variable.
    expect(() => new SecretCipher({ keys: [process.env.NO_SUCH_KEY as never] })).toThrow(
      '`mfa.encryption.keys[0]` is required (32 random bytes, or a random string of at least 32 characters), but it is undefined: is the environment variable it reads set?',
    );

    const error = (() => {
      try {
        new SecretCipher({ keys: ['short-secret-value'] });
      } catch (caught) {
        return caught as Error;
      }
    })();
    expect(error?.message).not.toContain('short-secret-value');
  });

  it('refuses a stored secret under 128 bits, an empty one included, whose codes anyone could compute', async () => {
    for (const short of ['', base32Encode(Buffer.alloc(15, 9))]) {
      const store = new InMemoryMfaStore();
      await store.saveTotp('u1', { secret: short, confirmed: true });
      const plaintext = service(store, { mfa: { now: () => clock, encryption: false } });
      await expect(plaintext.verifyTotp('u1', hotp(base32Decode(short), Math.floor(clock / 30_000)))).resolves.toBe(false);

      const migrating = service(store, { mfa: { now: () => clock, encryption: { keys: [K1], migratePlaintext: true } } });
      await expect(migrating.verifyTotp('u1', hotp(base32Decode(short), Math.floor(clock / 30_000)))).resolves.toBe(false);
    }
  });

  it('re-encrypting after a good code never brings back an authenticator disabled meanwhile', async () => {
    const store = new InMemoryMfaStore();
    const secret = await enrolled(withKeys(store, K1));
    const rotated = withKeys(store, K2, K1); // K2 encrypts now; the secret is still under K1

    // disable() lands between the code's check and the re-encryption's write.
    const claim = store.claimTotpStep.bind(store);
    vi.spyOn(store, 'claimTotpStep').mockImplementation(async (userId, step) => {
      const claimed = await claim(userId, step);
      await store.saveTotp(userId, null);
      return claimed;
    });

    await rotated.verifyTotp('u1', code(secret));
    await expect(store.getTotp('u1')).resolves.toBeUndefined();
  });

  it('a key-rotation job never brings back an authenticator replaced meanwhile', async () => {
    const store = new InMemoryMfaStore();
    await enrolled(withKeys(store, K1));
    const app = withKeys(store, K1);
    const job = withKeys(store, K2, K1);

    // The user confirms a new authenticator between the job's read and its write.
    let next = '';
    let replacing = false;
    const get = store.getTotp.bind(store);
    vi.spyOn(store, 'getTotp').mockImplementation(async (userId) => {
      const record = await get(userId);
      if (!replacing) {
        replacing = true; // before enroll(), which reads again
        next = (await app.enroll(userId, userId, { replace: true })).secret;
        await app.confirm(userId, code(next));
      }
      return record;
    });

    await expect(job.reencrypt('u1')).resolves.toBe(false);
    await expect(withKeys(store, K2, K1).verifyTotp('u1', code(next, 1))).resolves.toBe(true); // the new one is active
  });

  it('migrates legacy plaintext secrets only when asked to', async () => {
    const store = new InMemoryMfaStore();
    const secret = await enrolled(service(store, { mfa: { now: () => clock, encryption: false } }));

    await expect(withKeys(store, K1).verifyTotp('u1', code(secret))).resolves.toBe(false);

    const migrating = service(store, { mfa: { now: () => clock, encryption: { keys: [K1], migratePlaintext: true } } });
    await expect(migrating.verifyTotp('u1', code(secret))).resolves.toBe(true);
    expect((await store.getTotp('u1'))!.secret.startsWith(`v1.${idOf(K1)}.`)).toBe(true);
  });
});
