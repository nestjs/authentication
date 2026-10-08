/**
 * `SessionService` and `SignInService` without a server: idle and absolute expiry details, the
 * writes a request costs, cookies; and `SignInService` in an HTTP exchange it reads the cookie from
 * and writes `Set-Cookie` to, or outside one.
 */
import { ForbiddenException, Logger } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/internal';
import {
  AuthenticationEvents,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  MfaService,
  SessionCookieProvider,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationEvent,
  type SessionOptions,
  type SessionRecord,
} from '../lib/index.js';
import { AuthenticationScope } from '../lib/context/authentication-scope.service.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';
import { PROVIDER_INIT } from '../lib/providers/authentication.provider.js';
import { storageWith, type User } from './fixtures.js';

const T0 = 1_700_000_000_000;

function sessionsWith(options: SessionOptions = {}, store = new InMemorySessionStore()) {
  let clock = T0;
  const events = new AuthenticationEvents();
  const seen: AuthenticationEvent[] = [];
  events.events$.subscribe((event) => seen.push(event));

  const sessions = new SessionService(
    storageWith({ sessions: store }),
    { session: { now: () => clock, idleTtl: '1m', absoluteTtl: '1h', touchInterval: '10s', cookie: { secure: false }, ...options } },
    events,
  );
  return { sessions, store, seen, tick: (ms: number) => (clock += ms) };
}

/** `SELECT … FROM sessions JOIN users …`: the session's user, read with it into `extra`. */
class JoiningSessionStore extends InMemorySessionStore {
  readonly users = new Map<string, User>([['u1', { id: 'u1', email: 'ada@example.com', name: 'Ada', roles: [] }]]);
  override async getSession(id: string) {
    const record = await super.getSession(id);
    const user = record && this.users.get(record.userId);
    return record && { ...record, ...(user && { extra: { user } }) };
  }
}

describe('SessionService', () => {
  it('writes lastActiveAt at most once per touchInterval', async () => {
    const { sessions, store, tick } = sessionsWith();
    const touch = vi.spyOn(store, 'touchSession');
    const { token, session } = await sessions.create('u1');

    tick(9_999);
    await sessions.validate(token);
    expect(touch).not.toHaveBeenCalled();

    tick(1);
    await sessions.validate(token);
    await sessions.validate(token);
    expect(touch.mock.calls).toEqual([[session.id, new Date(T0 + 10_000)]]);
  });

  it('returns the session as read when touchSession() fails, reporting it, and records activity on the next request', async () => {
    const { sessions, store, seen, tick } = sessionsWith();
    const { token, session } = await sessions.create('u1');
    const failure = new Error('lock wait timeout exceeded');
    const touch = vi.spyOn(store, 'touchSession').mockRejectedValueOnce(failure);
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);

    try {
      tick(10_000);
      const validated = await sessions.validate(token);
      expect(validated).toMatchObject({ id: session.id, userId: 'u1', lastActiveAt: new Date(T0) });
      expect((await store.getSession(session.id))!.lastActiveAt).toEqual(new Date(T0));
      expect(seen).toEqual([{ type: 'session-touch-failed', userId: 'u1', sessionId: session.id, error: failure }]);
      expect(seen[0]).toHaveProperty('error', failure);
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toContain('lock wait timeout exceeded');

      // Not touched, the session ends at its previous idle deadline, unless a later request records activity.
      tick(1);
      expect((await sessions.validate(token))!.lastActiveAt).toEqual(new Date(T0 + 10_001));
      expect(touch).toHaveBeenCalledTimes(2);
      expect((await store.getSession(session.id))!.lastActiveAt).toEqual(new Date(T0 + 10_001));
      expect(seen).toHaveLength(1);
    } finally {
      warn.mockRestore();
    }
  });

  it('warns once per spell of touch failures, publishing each, and logs once when a touch succeeds again', async () => {
    const { sessions, store, seen, tick } = sessionsWith();
    const { token, session } = await sessions.create('u1');
    const failure = new Error('read-only replica');
    const touchSession = store.touchSession.bind(store);
    let down = true;
    vi.spyOn(store, 'touchSession').mockImplementation((id, at) => (down ? Promise.reject(failure) : touchSession(id, at)));
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);

    try {
      for (let i = 0; i < 3; i++) {
        tick(10_000);
        expect(await sessions.validate(token)).toMatchObject({ id: session.id });
      }
      expect(seen).toEqual(Array(3).fill({ type: 'session-touch-failed', userId: 'u1', sessionId: session.id, error: failure }));
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toContain('read-only replica');
      expect(log).not.toHaveBeenCalled();

      // The next successful touch ends the spell: one line, with the count.
      down = false;
      tick(10_000);
      await sessions.validate(token);
      tick(10_000);
      await sessions.validate(token);
      expect(log).toHaveBeenCalledTimes(1);
      expect(String(log.mock.calls[0][0])).toContain('3 touches failed');
      expect(warn).toHaveBeenCalledTimes(1);

      // A new spell warns again.
      down = true;
      tick(10_000);
      await sessions.validate(token);
      expect(warn).toHaveBeenCalledTimes(2);
      expect(seen).toHaveLength(4);
    } finally {
      warn.mockRestore();
      log.mockRestore();
    }
  });

  it('with idleTtl 0, keeps an idle session until its absolute expiry', async () => {
    const { sessions, tick } = sessionsWith({ idleTtl: 0 });
    const { token } = await sessions.create('u1');

    tick(3_599_999);
    await expect(sessions.validate(token)).resolves.not.toBeNull();
    tick(1);
    await expect(sessions.validate(token)).resolves.toBeNull();
  });

  it('deletes a session past its absolute expiry, but keeps an idle one for the store to prune', async () => {
    const { sessions, store, tick } = sessionsWith();
    const idle = await sessions.create('u1');
    tick(60_000);
    await expect(sessions.validate(idle.token)).resolves.toBeNull();
    // Another instance may have touched it since this read: deleting it here could sign that user out.
    await expect(store.getSession(idle.session.id)).resolves.toBeDefined();

    const { sessions: long, store: longStore, tick: longTick } = sessionsWith({ idleTtl: 0 });
    const expired = await long.create('u1');
    longTick(3_600_000);
    await expect(long.validate(expired.token)).resolves.toBeNull();
    await expect(longStore.getSession(expired.session.id)).resolves.toBeUndefined();
  });

  it('never looks up tokens that are not well-formed', async () => {
    const { sessions, store } = sessionsWith();
    const get = vi.spyOn(store, 'getSession');
    for (const token of [undefined, '', 'short', `${'A'.repeat(43)}=`, 'A'.repeat(42) + '.']) {
      await expect(sessions.validate(token)).resolves.toBeNull();
    }
    expect(get).not.toHaveBeenCalled();
  });

  it('create() deletes the session it replaces, and ignores a `replacing` that is not a token', async () => {
    const { sessions, store } = sessionsWith();
    const old = await sessions.create('u1');
    const remove = vi.spyOn(store, 'deleteSession');

    await sessions.create('u1', { replacing: 'not-a-token' });
    expect(remove).not.toHaveBeenCalled();

    await sessions.create('u1', { replacing: old.token });
    expect(remove).toHaveBeenCalledWith(old.session.id);
    await expect(sessions.validate(old.token)).resolves.toBeNull();
  });

  it('stores metadata only when given, and keeps it across rotations unless the rotation changes it', async () => {
    const { sessions } = sessionsWith();
    expect((await sessions.create('u1')).session).not.toHaveProperty('metadata');

    const first = await sessions.create('u1', { metadata: { device: 'laptop' } });
    const rotated = (await sessions.rotate(first.session))!;
    expect(rotated.session.metadata).toEqual({ device: 'laptop' });
    expect(rotated.session.id).not.toBe(first.session.id);

    const renamed = (await sessions.rotate(rotated.session, { metadata: { device: 'work laptop' } }))!;
    expect(renamed.session.metadata).toEqual({ device: 'work laptop' });
  });

  it('hands back the `extra` the store read with the session, and never stores it, rotations included', async () => {
    const store = new JoiningSessionStore();
    const { sessions, tick } = sessionsWith({}, store);
    const create = vi.spyOn(store, 'createSession');
    const { token } = await sessions.create('u1');

    tick(10_000);
    const session = (await sessions.validate(token))!;
    expect(session.extra).toEqual({ user: store.users.get('u1') });

    const rotated = (await sessions.rotate(session, { mfa: 'verified' }))!;
    expect(create).toHaveBeenCalledTimes(2);
    expect(create.mock.calls[1][0]).not.toHaveProperty('extra');
    expect(rotated.session).not.toHaveProperty('extra');

    // The in-memory store doesn't keep an `extra` handed to it either.
    const plain = new InMemorySessionStore();
    await plain.createSession({ ...session, extra: { user: store.users.get('u1')! } });
    expect(await plain.getSession(session.id)).not.toHaveProperty('extra');
  });

  it('sets the cookie’s Max-Age to the session’s remaining lifetime', async () => {
    const { sessions, tick } = sessionsWith({ idleTtl: 0 });
    const issued = await sessions.create('u1');
    expect(issued.cookie).toMatch(/^sid=[\w-]{43}; Max-Age=3600; Path=\/; HttpOnly; SameSite=Lax$/);

    tick(600_000);
    expect((await sessions.rotate(issued.session))!.cookie).toContain('Max-Age=3000;');
  });

  it('clearCookie() expires the cookie with the attributes it was set with', () => {
    const { sessions } = sessionsWith({ cookie: { secure: true, sameSite: 'strict', domain: 'example.com' }, cookieName: 'app_sid' });
    expect(sessions.clearCookie()).toBe('app_sid=; Max-Age=0; Path=/; Domain=example.com; HttpOnly; Secure; SameSite=Strict');
  });

  it('revoke() refuses ids that are not strings without a lookup, and publishes nothing when it refuses', async () => {
    const { sessions, store, seen } = sessionsWith();
    const get = vi.spyOn(store, 'getSession');
    const mine = await sessions.create('u1');

    await expect(sessions.revoke({ id: mine.session.id } as never, { userId: 'u1' })).resolves.toBe(false);
    await expect(sessions.revoke('unknown', { userId: 'u1' })).resolves.toBe(false);
    expect(get).toHaveBeenCalledTimes(1);
    expect(seen).toEqual([]);
  });

  it('revokeAll({ except }) keeps that one session, and only for that user', async () => {
    const { sessions } = sessionsWith();
    const keep = await sessions.create('u1');
    const drop = await sessions.create('u1');
    const other = await sessions.create('u2');

    await sessions.revokeAll('u1', { except: keep.session.id });
    await expect(sessions.validate(keep.token)).resolves.not.toBeNull();
    await expect(sessions.validate(drop.token)).resolves.toBeNull();
    await expect(sessions.validate(other.token)).resolves.not.toBeNull();

    await sessions.revokeAll('u1', { except: other.session.id }); // another user's id keeps nothing of u1's
    await expect(sessions.validate(keep.token)).resolves.toBeNull();
  });

  it('metadataFor() calls `session.metadata` with the request, and only when there is one', () => {
    const metadata = vi.fn((request: { headers: Record<string, unknown>; ip?: string }) => ({ ip: request.ip }));
    const { sessions } = sessionsWith({ metadata });

    expect(sessions.metadataFor(undefined)).toBeUndefined();
    expect(sessions.metadataFor({ headers: {}, ip: '::1' })).toEqual({ ip: '::1' });
    expect(metadata).toHaveBeenCalledTimes(1);
    expect(sessionsWith().sessions.metadataFor({ headers: {} })).toBeUndefined();
  });
});

describe('SignInService', () => {
  function setup(options: SessionOptions = {}) {
    const { sessions, store, seen, tick } = sessionsWith(options);
    const refreshTokens = new InMemoryRefreshTokenStore();
    const mfa = new MfaService(storageWith(), { mfa: { issuer: 'Test', encryption: false } });
    const tokens = new TokenService(storageWith({ refreshTokens }), { accessToken: { key: 'x'.repeat(32) } });
    const scope = new AuthenticationScope();
    const adapterHost = new HttpAdapterHost();
    adapterHost.httpAdapter = {
      appendHeader: (response: { cookies: string[] }, name: string, value: string) => {
        expect(name).toBe('Set-Cookie');
        response.cookies.push(value);
      },
    } as never;

    const events = new AuthenticationEvents();
    events.events$.subscribe((event) => seen.push(event));
    const signIn = new SignInService(sessions, mfa, tokens, scope, adapterHost, events);

    class Handler {
      handle() {}
    }

    /** Runs `fn` as the handler of an HTTP request with these headers. */
    const inRequest = async <R>(headers: Record<string, string>, fn: () => Promise<R>, method = 'POST') => {
      const request = { headers, method, ip: '203.0.113.9' };
      const response = { cookies: [] as string[] };
      const context = new ExecutionContextHost([request, response], Handler, Handler.prototype.handle);
      context.setType('http');
      const result = await scope.run({ result: null, context }, fn);
      return { result, cookies: response.cookies };
    };
    const cookieHeader = (setCookie: string) => ({ cookie: setCookie.split(';')[0] });

    return { signIn, sessions, store, mfa, tokens, seen, tick, inRequest, cookieHeader };
  }

  it('sets the cookie on the response, and returns it outside HTTP without setting anything', async () => {
    const { signIn, inRequest, sessions } = setup();

    const { result, cookies } = await inRequest({}, () => signIn.signIn('u1'));
    expect(cookies).toEqual([result.cookie]);

    const outside = await signIn.signIn('u1');
    expect(outside.cookie).toMatch(/^sid=/);
    expect(await sessions.list('u1')).toHaveLength(2);
  });

  it('refuses a sign-in posted from another origin with a 403, creating no session', async () => {
    const { signIn, inRequest, sessions, seen } = setup();

    const error = await inRequest({ origin: 'https://evil.test', host: 'api.test' }, () => signIn.signIn('u1')).catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenException);
    expect(error.message).toBe('Cross-origin sign-in refused');
    expect(await sessions.list('u1')).toEqual([]);
    expect(seen).toEqual([]);

    // From a trusted origin, it is a sign-in like any other.
    const trusted = setup({ trustedOrigins: ['https://app.test'] });
    const { cookies } = await trusted.inRequest({ origin: 'https://app.test', host: 'api.test' }, () => trusted.signIn.signIn('u1'));
    expect(cookies).toHaveLength(1);
  });

  it('merges `session.metadata` from the request with the caller’s own, the caller’s winning', async () => {
    const { signIn, inRequest, seen } = setup({
      metadata: (request) => ({ ip: request.ip, userAgent: request.headers['user-agent'] ?? null }),
    });

    const { result } = await inRequest({ 'user-agent': 'Test/1' }, () =>
      signIn.signIn('u1', { method: 'password', metadata: { userAgent: 'overridden', device: 'kiosk' } }),
    );
    expect(result.session.metadata).toEqual({ ip: '203.0.113.9', userAgent: 'overridden', device: 'kiosk' });
    expect(seen).toEqual([
      { type: 'sign-in', userId: 'u1', sessionId: result.session.id, method: 'password', metadata: result.session.metadata },
    ]);
  });

  it('publishes a sign-in without the fields it has no value for', async () => {
    const { signIn, seen } = setup();
    const { session } = await signIn.signIn('u1');
    expect(seen).toEqual([{ type: 'sign-in', userId: 'u1', sessionId: session.id }]);
    expect(session).not.toHaveProperty('metadata');
  });

  it('signOut(): false without a cookie; false, clearing the cookie, for a dead one; true and an event for a live one', async () => {
    const { signIn, inRequest, cookieHeader, seen } = setup();

    const bare = await inRequest({}, () => signIn.signOut());
    expect(bare).toEqual({ result: false, cookies: [] });

    const stale = await inRequest({ cookie: `sid=${'A'.repeat(43)}` }, () => signIn.signOut());
    expect(stale.result).toBe(false);
    expect(stale.cookies).toEqual([expect.stringMatching(/^sid=; Max-Age=0; /)]);

    const { result: issued } = await inRequest({}, () => signIn.signIn('u1'));
    seen.length = 0;
    const live = await inRequest(cookieHeader(issued.cookie), () => signIn.signOut());
    expect(live.result).toBe(true);
    expect(live.cookies).toEqual([expect.stringMatching(/^sid=; Max-Age=0; /)]);
    expect(seen).toEqual([{ type: 'sign-out', userId: 'u1', sessionId: issued.session.id }]);
  });

  it('signOut() and signOutEverywhere() go ahead when recording the session’s activity fails', async () => {
    const { signIn, inRequest, cookieHeader, store, seen, tick } = setup();
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(store, 'touchSession').mockRejectedValue(new Error('read-only replica'));

    try {
      const { result: one } = await inRequest({}, () => signIn.signIn('u1'));
      const { result: two } = await inRequest({}, () => signIn.signIn('u1'));
      tick(10_000);
      seen.length = 0;

      const signedOut = await inRequest(cookieHeader(one.cookie), () => signIn.signOut());
      expect(signedOut.result).toBe(true);
      expect(signedOut.cookies).toEqual([expect.stringMatching(/^sid=; Max-Age=0; /)]);
      await expect(store.getSession(one.session.id)).resolves.toBeUndefined();

      const everywhere = await inRequest(cookieHeader(two.cookie), () => signIn.signOutEverywhere('u1'));
      expect(everywhere.cookies).toEqual([expect.stringMatching(/^sid=; Max-Age=0; /)]);
      await expect(store.getSession(two.session.id)).resolves.toBeUndefined();

      expect(seen.map((event) => event.type)).toEqual(['session-touch-failed', 'sign-out', 'session-touch-failed', 'sign-out']);
    } finally {
      warn.mockRestore();
    }
  });

  it('signOut() deletes the session even where it looks idle: another instance may still take it', async () => {
    const { signIn, inRequest, cookieHeader, store, tick } = setup({ idleTtl: '1m', touchInterval: '10s' });
    const { result: issued } = await inRequest({}, () => signIn.signIn('u1'));
    tick(61_000); // idle here; an instance with a lagging clock, or a longer idleTtl, still accepts it

    const signedOut = await inRequest(cookieHeader(issued.cookie), () => signIn.signOut());
    expect(signedOut.result).toBe(false);
    await expect(store.getSession(issued.session.id)).resolves.toBeUndefined();
  });

  it('rotateSession() gives the browser a new cookie for the same user, and null without a session', async () => {
    const { signIn, inRequest, cookieHeader, sessions } = setup();
    await expect(inRequest({}, () => signIn.rotateSession())).resolves.toEqual({ result: null, cookies: [] });

    const { result: issued } = await inRequest({}, () => signIn.signIn('u1'));
    const { result: rotated, cookies } = await inRequest(cookieHeader(issued.cookie), () => signIn.rotateSession(), 'GET');
    expect(cookies).toEqual([rotated!.cookie]);
    expect(rotated!.session.userId).toBe('u1');
    await expect(sessions.validate(issued.token)).resolves.toBeNull();
    await expect(sessions.validate(rotated!.token)).resolves.not.toBeNull();
  });

  it('completeMfa() needs a code, and a session, before it asks the authenticator', async () => {
    const { signIn, inRequest, mfa } = setup();
    const verify = vi.spyOn(mfa, 'verifyTotp');

    await expect(signIn.completeMfa({})).resolves.toBeNull();
    await expect(signIn.completeMfa({ code: '' })).resolves.toBeNull();
    await expect(inRequest({}, () => signIn.completeMfa({ code: '123456' }))).resolves.toEqual({ result: null, cookies: [] });
    expect(verify).not.toHaveBeenCalled();
  });

  it('confirmMfa() rotates only a session of that user: another user’s browser only confirms', async () => {
    const { signIn, inRequest, cookieHeader, mfa, sessions } = setup();
    const { secret } = await mfa.enroll('u1', 'ada@example.com');
    const code = hotp(base32Decode(secret), Math.floor(Date.now() / 30_000));

    const { result: bobs } = await inRequest({}, () => signIn.signIn('u2'));
    const confirmed = await inRequest(cookieHeader(bobs.cookie), () => signIn.confirmMfa('u1', code));
    expect(confirmed).toEqual({ result: true, cookies: [] });
    await expect(sessions.validate(bobs.token)).resolves.not.toHaveProperty('mfa');
    await expect(mfa.isEnrolled('u1')).resolves.toBe(true);

    await expect(signIn.confirmMfa('u1', '000000')).resolves.toBe(false);
  });

  it('signOutEverywhere() clears this browser’s cookie only when it belongs to that user', async () => {
    const { signIn, inRequest, cookieHeader, tokens, sessions, seen } = setup();
    const { result: ada } = await inRequest({}, () => signIn.signIn('u1'));
    const { result: bob } = await inRequest({}, () => signIn.signIn('u2'));
    const pair = await tokens.issue('u1');
    seen.length = 0;

    const fromBob = await inRequest(cookieHeader(bob.cookie), () => signIn.signOutEverywhere('u1'));
    expect(fromBob.cookies).toEqual([]);
    await expect(sessions.validate(ada.token)).resolves.toBeNull();
    await expect(sessions.validate(bob.token)).resolves.not.toBeNull();
    await expect(tokens.refresh(pair.refreshToken)).rejects.toMatchObject({ reason: 'invalid' });
    expect(seen).toEqual([{ type: 'sign-out', userId: 'u1', everywhere: true }]);

    const fromOwn = await inRequest(cookieHeader(bob.cookie), () => signIn.signOutEverywhere('u2'));
    expect(fromOwn.cookies).toEqual([expect.stringMatching(/^sid=; Max-Age=0; /)]);
  });
});

describe('SessionCookieProvider', () => {
  class SessionAuth extends SessionCookieProvider<User> {
    readonly seen: SessionRecord[] = [];
    validate(session: SessionRecord) {
      this.seen.push(session);
      // Typed by `sessionExtra` on `AuthenticationTypes` (tests/fixtures.ts).
      const user: User | undefined = session.extra?.user;
      return user ?? null;
    }
  }

  function setup() {
    const store = new JoiningSessionStore();
    const { sessions } = sessionsWith({}, store);
    const provider = new SessionAuth();
    provider[PROVIDER_INIT]((() => sessions) as never);
    const authenticate = (cookie: string) => {
      const context = new ExecutionContextHost([{ headers: { cookie: cookie.split(';')[0] }, method: 'GET' }, {}]);
      context.setType('http');
      return provider.authenticate(context);
    };
    return { store, sessions, provider, authenticate };
  }

  it('hands validate() the `extra` the store read with the session, and leaves it out of the result', async () => {
    const { store, sessions, provider, authenticate } = setup();
    const { cookie, session } = await sessions.create('u1');

    const result = await authenticate(cookie);
    expect(provider.seen).toEqual([{ ...session, extra: { user: store.users.get('u1') } }]);
    expect(result).toEqual({ user: store.users.get('u1'), session, mfa: undefined });
    expect(result!.session).not.toHaveProperty('extra');
  });
});
