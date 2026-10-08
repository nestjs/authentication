import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import { connect, type ClientHttp2Session, type IncomingHttpHeaders } from 'node:http2';
import type { INestApplication } from '@nestjs/common';
import { FastifyAdapter } from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationContext,
  AuthenticationError,
  AuthenticationEvents,
  JwtSigner,
  AuthenticationStorage,
  type AuthenticationEvent,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';
import { AppModule, AppConfig, PASSWORDS, UsersRepository, outbox } from './fixtures.js';

const totpNow = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(Date.now() / 30_000) + offset);
const cookieOf = (res: request.Response, name = 'sid') =>
  ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith(`${name}=`))!.split(';')[0];
const claimsOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

describe.each(adapters.map((a) => a.name))('authentication e2e (%s)', (adapter) => {
  let app: INestApplication;
  const http = () => request(app.getHttpServer());
  const login = async (email: string, extraCookie?: string, userAgent?: string) => {
    let req = http().post('/auth/login').send({ email, password: PASSWORDS[email] });

    if (extraCookie) {
      req = req.set('Cookie', extraCookie);
    }
    if (userAgent) {
      req = req.set('User-Agent', userAgent);
    }

    const res = await req.expect(200);
    return { res, cookie: cookieOf(res) };
  };
  const token = async (email: string) =>
    (await http().post('/auth/token').send({ email, password: PASSWORDS[email] }).expect(200)).body as {
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
    };

  beforeAll(async () => {
    app = await createApp(adapter, AppModule);
  });
  afterAll(() => app.close());

  describe('password sign-in + session cookie', () => {
    it('answers 401 without credentials, with every provider challenge', async () => {
      const res = await http().get('/me').expect(401);
      expect(res.headers['www-authenticate']).toBe('Bearer realm="api", ApiKey header="x-api-key"');
    });

    it('signIn() sets an HttpOnly cookie on the response and the cookie authenticates', async () => {
      const { res, cookie } = await login('bob@example.com');
      expect(res.headers['set-cookie']).toEqual([
        expect.stringMatching(/^sid=[\w-]{43}; Max-Age=604800; Path=\/; HttpOnly; SameSite=Lax$/),
      ]);

      const me = await http().get('/me').set('Cookie', `theme=dark; ${cookie}`).expect(200);
      expect(me.body.user).toEqual({ id: 'u2', email: 'bob@example.com', name: 'Bob', roles: ['viewer'] });
      expect(me.body.email).toBe('bob@example.com');
      expect(me.body.session).toMatchObject({ userId: 'u2' });
      expect(cookie).not.toContain(me.body.session.id); // stored hashed
    });

    it('rejects a wrong password and an unknown account the same way', async () => {
      await http().post('/auth/login').send({ email: 'bob@example.com', password: 'nope' }).expect(401);
      await http().post('/auth/login').send({ email: 'nobody@example.com', password: 'nope' }).expect(401);
    });

    it('discards the browser’s previous session on sign-in (fixation defence)', async () => {
      const first = await login('bob@example.com');
      const second = await login('bob@example.com', first.cookie);
      await http().get('/me').set('Cookie', first.cookie).expect(401);
      await http().get('/me').set('Cookie', second.cookie).expect(200);
    });

    it('stores `session.metadata` for every sign-in', async () => {
      const { cookie } = await login('bob@example.com', undefined, 'Firefox/130');
      const list = await http().get('/auth/sessions').set('Cookie', cookie).expect(200);
      expect(list.body.find((s: { current: boolean }) => s.current).metadata).toEqual({ userAgent: 'Firefox/130' });
    });

    it('treats unknown or malformed cookies as anonymous', async () => {
      await http().get('/me').set('Cookie', `sid=${'x'.repeat(43)}`).expect(401);
      await http().get('/feed').set('Cookie', 'sid=garbage').expect(200, { personalizedFor: null });
    });

    it('signs out, and lists and revokes other sessions', async () => {
      const a = await login('bob@example.com');
      const b = await login('bob@example.com');

      const list = await http().get('/auth/sessions').set('Cookie', a.cookie).expect(200);
      expect(list.body.filter((s: { current: boolean }) => s.current)).toHaveLength(1);
      expect(list.body.length).toBeGreaterThanOrEqual(2);

      await http().post('/auth/sessions/revoke-others').set('Cookie', a.cookie).expect(204);
      await http().get('/me').set('Cookie', b.cookie).expect(401);

      const out = await http().post('/auth/logout').set('Cookie', a.cookie).expect(204);
      expect(out.headers['set-cookie']).toEqual([expect.stringMatching(/^sid=; Max-Age=0;/)]);
      await http().get('/me').set('Cookie', a.cookie).expect(401);
    });

    it('revoke(id, { userId }) ends only the user’s own sessions', async () => {
      const bob = await login('bob@example.com');
      const other = await login('bob@example.com');
      const alice = await login('alice@example.com');

      const list = await http().get('/auth/sessions').set('Cookie', bob.cookie).expect(200);
      const otherId = list.body.find((s: { id: string; current: boolean }) => !s.current).id;

      // Another user passing Bob's session id: 404, and the session lives on.
      await http().delete(`/auth/sessions/${otherId}`).set('Cookie', alice.cookie).expect(404);
      await http().delete(`/auth/sessions/${otherId}`).set('x-api-key', 'key-ci').expect(404);
      await http().get('/me').set('Cookie', other.cookie).expect(200);

      await http().delete(`/auth/sessions/${otherId}`).set('Cookie', bob.cookie).expect(204);
      await http().get('/me').set('Cookie', other.cookie).expect(401);
    });

    it('rotateSession() moves this browser to a new session id', async () => {
      const { cookie } = await login('bob@example.com');
      const res = await http().post('/auth/sessions/rotate').set('Cookie', cookie).expect(204);
      const rotated = cookieOf(res);
      expect(rotated).not.toBe(cookie);
      await http().get('/me').set('Cookie', cookie).expect(401);
      await http().get('/me').set('Cookie', rotated).expect(200);
    });

    it('signOut() acts on the cookie only: a bearer token gets 401 and signs nothing out', async () => {
      const { accessToken } = await token('bob@example.com');
      const res = await http().post('/auth/logout').set('Authorization', `Bearer ${accessToken}`).expect(401);
      expect(res.headers['www-authenticate']).toBeUndefined();
      await http().get('/me').set('Authorization', `Bearer ${accessToken}`).expect(200); // the token still works

      const { cookie } = await login('bob@example.com');
      await http().post('/auth/logout').set('Cookie', cookie).set('Authorization', `Bearer ${accessToken}`).expect(204);
      await http().get('/me').set('Cookie', cookie).expect(401);
    });

    it('@Authenticate({ providers }) keeps a route to the cookie session', async () => {
      const { accessToken } = await token('bob@example.com');
      const res = await http().post('/auth/sessions/rotate').set('Authorization', `Bearer ${accessToken}`).expect(401);
      expect(res.headers['www-authenticate']).toBeUndefined(); // only the cookie provider counts here
    });

    it('signOutEverywhere() ends every session and refresh token, and clears this browser’s cookie', async () => {
      const laptop = await login('bob@example.com');
      const phone = await login('bob@example.com');
      const mobile = await token('bob@example.com');

      const res = await http().post('/auth/logout-everywhere').set('Cookie', laptop.cookie).expect(204);
      expect(res.headers['set-cookie']).toEqual([expect.stringMatching(/^sid=; Max-Age=0;/)]);
      await http().get('/me').set('Cookie', phone.cookie).expect(401);
      await http().post('/auth/refresh').send({ refreshToken: mobile.refreshToken }).expect(401);
    });

    it('ignores the cookie on cross-origin writes (CSRF), but not on same-origin ones', async () => {
      const { cookie } = await login('bob@example.com');
      const host = `127.0.0.1:${app.getHttpServer().address().port}`;

      await http().get('/me').set('Cookie', cookie).set('Origin', 'https://evil.test').expect(200); // reads are fine
      await http().post('/auth/sessions/revoke-others').set('Cookie', cookie).set('Origin', 'https://evil.test').expect(401);
      await http().post('/auth/sessions/revoke-others').set('Cookie', cookie).set('Origin', 'null').expect(401);
      await http().post('/auth/sessions/revoke-others').set('Cookie', cookie).set('Sec-Fetch-Site', 'cross-site').expect(401);
      await http().post('/auth/sessions/revoke-others').set('Cookie', cookie).set('Origin', `http://${host}`).expect(204);
      await http().post('/auth/sessions/revoke-others').set('Cookie', cookie).expect(204); // non-browser client

      // The same check guards SignInService: a cross-site page cannot sign the browser out.
      await http().post('/auth/logout').set('Cookie', cookie).set('Origin', 'https://evil.test').expect(401);
      await http().get('/me').set('Cookie', cookie).expect(200);
    });

    it('refuses to sign the browser in from another origin (login CSRF)', async () => {
      const bob = { email: 'bob@example.com', password: PASSWORDS['bob@example.com'] };
      for (const header of [{ Origin: 'https://evil.test' }, { 'Sec-Fetch-Site': 'cross-site' }]) {
        const res = await http().post('/auth/login').set(header).send(bob).expect(403);
        expect(res.body).toEqual({ message: 'Cross-origin sign-in refused', error: 'Forbidden', statusCode: 403 });
        expect(res.headers['set-cookie']).toBeUndefined();
      }

      // A magic link of the attacker's, posted from the attacker's page, signs no one in either:
      // not without the transaction cookie of the browser that requested it (401), and not with
      // it (403, from SignInService).
      const requested = await http().post('/auth/magic').send({ email: 'bob@example.com' }).expect(202);
      const tokenParam = new URL(outbox.at(-1)!.url).searchParams.get('token')!;

      await http().post('/auth/magic/consume').set('Origin', 'https://evil.test').send({ token: tokenParam }).expect(401);

      const res = await http()
        .post('/auth/magic/consume')
        .set('Origin', 'https://evil.test')
        .set('Cookie', cookieOf(requested, '__Host-magic_link_tx'))
        .send({ token: tokenParam });
      expect(res.status).toBe(403);
      expect(res.headers['set-cookie']).toEqual(['__Host-magic_link_tx=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax']);
      // Same-origin pages and non-browser clients sign in as before.
      const host = `127.0.0.1:${app.getHttpServer().address().port}`;
      await http().post('/auth/login').set('Origin', `http://${host}`).send(bob).expect(200);
      await http().post('/auth/login').send(bob).expect(200);
    });

    it('drops the session when the user no longer exists', async () => {
      const users = app.get(UsersRepository);
      const hash = users.findByEmail('bob@example.com')!;
      const { cookie } = await login('bob@example.com');

      users.delete('u2');
      try {
        await http().get('/me').set('Cookie', cookie).expect(401);
      } finally {
        (users as any).users.set('u2', hash);
      }
    });
  });

  describe('bearer JWT (ES256) and refresh tokens', () => {
    it('issues an ES256 access token from the `accessToken` options, verified with them', async () => {
      const issued = await token('bob@example.com');
      expect(issued).toEqual({ accessToken: expect.any(String), refreshToken: expect.stringMatching(/^[\w-]{43}$/), expiresIn: 300 });

      const header = JSON.parse(Buffer.from(issued.accessToken.split('.')[0], 'base64url').toString());
      expect(header).toEqual({ alg: 'ES256', typ: 'JWT', kid: 'k1' });
      expect(claimsOf(issued.accessToken)).toMatchObject({ sub: 'u2', amr: ['pwd'], iss: 'https://api.test', aud: 'nest-api' });

      const res = await http().get('/me').set('Authorization', `Bearer ${issued.accessToken}`).expect(200);
      expect(res.body.user.id).toBe('u2');
      expect(res.body.session).toMatchObject({ sub: 'u2', iss: 'https://api.test', aud: 'nest-api' });
    });

    it('answers 401 with an RFC 6750 error for a token signed by another key', async () => {
      const config = app.get(AppConfig);
      const { generateKeyPairSync } = await import('node:crypto');
      const forged = new JwtSigner({
        key: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey,
        issuer: config.issuer,
        audience: config.audience,
      }).sign({ sub: 'u1' });

      const res = await http().get('/me').set('Authorization', `Bearer ${forged}`).expect(401);
      expect(res.headers['www-authenticate']).toBe(
        'Bearer realm="api", error="invalid_token", error_description="invalid signature"',
      );
    });

    it('rotates refresh tokens and revokes the family on reuse; the error is a 401', async () => {
      const first = await token('bob@example.com');
      const second = (await http().post('/auth/refresh').send({ refreshToken: first.refreshToken }).expect(200)).body;
      await http().get('/me').set('Authorization', `Bearer ${second.accessToken}`).expect(200);

      // The stolen first token comes back: reuse. Its successor dies with it.
      const reuse = await http().post('/auth/refresh').send({ refreshToken: first.refreshToken }).expect(401);
      expect(reuse.text).toBe('{"message":"Refresh token reused","error":"Unauthorized","statusCode":401}');

      const dead = await http().post('/auth/refresh').send({ refreshToken: second.refreshToken }).expect(401);
      expect(dead.body.message).toBe('Refresh token invalid');
      await http().post('/auth/refresh').send({}).expect(401);
    });

    it('never lets the app’s own `amr` values pass a token off as MFA-verified', async () => {
      const bob = { email: 'bob@example.com', password: PASSWORDS['bob@example.com'] };
      const forged = (await http().post('/auth/token').send({ ...bob, amr: ['pwd', 'mfa', 'otp', 'hwk'] }).expect(200)).body;
      expect(claimsOf(forged.accessToken).amr).toEqual(['pwd']);

      await http().get('/me').set('Authorization', `Bearer ${forged.accessToken}`).expect(200);
      await http().get('/me/sensitive').set('Authorization', `Bearer ${forged.accessToken}`).expect(401);

      const refreshed = (await http().post('/auth/refresh').send({ refreshToken: forged.refreshToken }).expect(200)).body;
      await http().get('/me/sensitive').set('Authorization', `Bearer ${refreshed.accessToken}`).expect(401);
    });

    it('leaves other Authorization schemes to other providers', async () => {
      await http().get('/me').set('Authorization', 'Basic dTpw').set('x-api-key', 'key-ci').expect(200);
    });
  });

  describe('API key (hand-written provider)', () => {
    it('authenticates a known key and rejects an unknown one with its own challenge', async () => {
      const ok = await http().get('/me').set('x-api-key', 'key-ci').expect(200);
      expect(ok.body.session).toEqual({ keyId: 'k1' });
      const bad = await http().get('/me').set('x-api-key', 'nope').expect(401);
      expect(bad.headers['www-authenticate']).toBe('ApiKey header="x-api-key"');
      // Nest's own UnauthorizedException body, with the provider's message.
      expect(bad.body).toEqual({ message: 'unknown API key', error: 'Unauthorized', statusCode: 401 });
    });
  });

  describe('@Public / @Authenticate', () => {
    it('@Public never calls providers, even with credentials', async () => {
      const { accessToken } = await token('bob@example.com');
      await http()
        .get('/public')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200, { open: true, user: null, contextUser: null });
    });

    it('@Authenticate() re-enables authentication under a @Public class', async () => {
      await http().get('/public/strict').expect(401);
      await http().get('/public/strict').set('x-api-key', 'key-ci').expect(200, { id: 'svc-ci' });
    });

    it('optional: resolves the user if present, and rejects invalid credentials', async () => {
      await http().get('/feed').expect(200, { personalizedFor: null });
      await http().get('/feed').set('x-api-key', 'key-ci').expect(200, { personalizedFor: 'svc-ci' });
      await http().get('/feed').set('Authorization', 'Bearer not.a.jwt').expect(401);
    });

    it('requireUser() in a service answers 401 for an anonymous caller', async () => {
      const res = await http().get('/feed/mine').expect(401);
      expect(res.text).toBe('{"message":"Unauthorized","statusCode":401}'); // as `new UnauthorizedException()`
      await http().get('/feed/mine').set('x-api-key', 'key-ci').expect(200, { id: 'svc-ci' });
    });

    it('the guard answers a caller without credentials with that body and `code: missing_credentials`', async () => {
      const res = await http().get('/me').expect(401);
      expect(res.text).toBe('{"message":"Unauthorized","statusCode":401,"code":"missing_credentials"}');
    });
  });

  describe('MFA (TOTP)', () => {
    let secret: string;
    let recoveryCodes: string[];
    let usedCode: string;

    it('enrolls and confirms an authenticator', async () => {
      const { cookie } = await login('alice@example.com');
      const enrolled = await http().post('/auth/mfa/enroll').set('Cookie', cookie).expect(201);
      secret = enrolled.body.secret;

      const stored = (await app.get(AuthenticationStorage).mfa.getTotp('u1'))!.secret;
      expect(stored).toMatch(/^v1\.[\w-]{8}\./); // encrypted at rest, under the key's derived id
      expect(stored).not.toContain(secret);
      expect(enrolled.body.uri).toBe(
        `otpauth://totp/Nest%20POC:alice%40example.com?secret=${secret}&issuer=Nest+POC&algorithm=SHA1&digits=6&period=30`,
      );

      await http().get('/me/sensitive').set('Cookie', cookie).expect(401); // no second factor yet
      await http().post('/auth/mfa/confirm').set('Cookie', cookie).send({ code: '000000' }).expect(401);

      const confirmed = await http()
        .post('/auth/mfa/confirm')
        .set('Cookie', cookie)
        .send({ code: totpNow(secret, -1) })
        .expect(200);
      recoveryCodes = confirmed.body.recoveryCodes;
      expect(recoveryCodes).toHaveLength(10);

      // confirmMfa(): the code proved this browser has the authenticator, so the session is
      // MFA-verified from here on, under a new id. No second sign-in, no second code.
      const verified = cookieOf(confirmed);
      expect(verified).not.toBe(cookie);
      await http().get('/me/sensitive').set('Cookie', cookie).expect(401);
      await http().get('/me/sensitive').set('Cookie', verified).expect(200, { ok: true });
    });

    it('confirming from a token client only confirms: no session becomes verified', async () => {
      const bob = await login('bob@example.com');
      const bearer = `Bearer ${(await token('bob@example.com')).accessToken}`;
      const enrolled = await http().post('/auth/mfa/enroll').set('Authorization', bearer).expect(201);

      const confirmed = await http().post('/auth/mfa/confirm').set('Authorization', bearer).send({ code: totpNow(enrolled.body.secret) }).expect(200);
      expect(confirmed.headers['set-cookie']).toBeUndefined();

      const store = app.get(AuthenticationStorage).mfa;
      expect((await store.getTotp('u2'))!.confirmed).toBe(true);
      await http().get('/me/sensitive').set('Cookie', bob.cookie).expect(401); // Bob’s password-only browser session stays so
      await http().get('/me/sensitive').set('Authorization', bearer).expect(401);

      await store.saveTotp('u2', null); // Bob stays password-only for the tests below
      await store.saveRecoveryCodes('u2', []);
    });

    it('signs in to a pending session that counts as signed in nowhere until completeMfa()', async () => {
      const { res, cookie } = await login('alice@example.com');
      expect(res.body).toEqual({ mfa: 'pending' });
      const denied = await http().get('/me').set('Cookie', cookie).expect(401);
      expect(denied.text).toBe('{"message":"Second factor required","error":"mfa_required","statusCode":401,"code":"mfa_required"}');
      await http().get('/feed').set('Cookie', cookie).expect(200, { personalizedFor: null });

      usedCode = totpNow(secret);
      const done = await http().post('/auth/mfa').set('Cookie', cookie).send({ code: usedCode }).expect(200);
      const upgraded = cookieOf(done);
      expect(upgraded).not.toBe(cookie); // rotated on privilege change

      await http().get('/me').set('Cookie', cookie).expect(401);
      await http().get('/me/sensitive').set('Cookie', upgraded).expect(200, { ok: true });
    });

    it('refuses a replayed code', async () => {
      const { cookie } = await login('alice@example.com');
      // Still inside the ±1 step window, but that step was already used.
      await http().post('/auth/mfa').set('Cookie', cookie).send({ code: usedCode }).expect(401);
    });

    it('counts a wrong code against the lockout, but not a request with no code at all', async () => {
      const { cookie } = await login('alice@example.com');
      const store = app.get(AuthenticationStorage).mfa;
      const failures = () => store.countMfaFailures('u1', 15 * 60_000, Date.now());
      const before = await failures();

      await http().post('/auth/mfa').set('Cookie', cookie).send({}).expect(401);
      await http().post('/auth/mfa').set('Cookie', cookie).send({ code: '' }).expect(401);
      expect(await failures()).toBe(before); // a client bug, not a guess (as TokenService.issue() without a secondFactor)

      await http().post('/auth/mfa').set('Cookie', cookie).send({ code: '000000' }).expect(401);
      expect(await failures()).toBe(before + 1);
    });

    it('completes MFA for the cookie session only, never for a bearer token', async () => {
      const { accessToken } = await token('bob@example.com');
      await http().post('/auth/mfa').set('Authorization', `Bearer ${accessToken}`).send({ code: '123456' }).expect(401);
    });

    let verifiedAccess: string;

    it('asks a token client of an enrolled user for the second factor', async () => {
      const alice = { email: 'alice@example.com', password: PASSWORDS['alice@example.com'] };
      const missing = await http().post('/auth/token').send(alice).expect(401);
      expect(missing.text).toBe('{"message":"Second factor required","error":"mfa_required","statusCode":401,"code":"mfa_required"}');
      const wrong = await http().post('/auth/token').send({ ...alice, code: usedCode }).expect(401); // a replay
      expect(wrong.body).toEqual({ message: 'Invalid code', error: 'mfa_required', code: 'mfa_required', statusCode: 401 });
    });

    it('keeps tokens issued with a second factor MFA-verified across refreshes', async () => {
      const issued = await http()
        .post('/auth/token')
        .send({ email: 'alice@example.com', password: PASSWORDS['alice@example.com'], code: totpNow(secret, 1) })
        .expect(200);
      let { accessToken, refreshToken } = issued.body;

      for (let i = 0; i < 2; i++) {
        await http().get('/me/sensitive').set('Authorization', `Bearer ${accessToken}`).expect(200);
        ({ accessToken, refreshToken } = (await http().post('/auth/refresh').send({ refreshToken }).expect(200)).body);
      }

      expect(claimsOf(accessToken).amr).toEqual(['pwd', 'mfa']);
      await http().get('/me/sensitive').set('Authorization', `Bearer ${accessToken}`).expect(200);
      verifiedAccess = accessToken;

      // Password-only families stay password-only.
      const bob = await token('bob@example.com');
      const refreshed = (await http().post('/auth/refresh').send({ refreshToken: bob.refreshToken }).expect(200)).body;
      await http().get('/me/sensitive').set('Authorization', `Bearer ${refreshed.accessToken}`).expect(401);
    });

    it('refuses to enroll over the confirmed authenticator; replacing it needs a verified caller', async () => {
      const store = app.get(AuthenticationStorage).mfa;
      const before = (await store.getTotp('u1'))!;

      const bob = await login('bob@example.com'); // password-only session
      await http().post('/auth/mfa/replace').set('Cookie', bob.cookie).expect(401);

      const pending = await login('alice@example.com');
      await http().post('/auth/mfa/enroll').set('Cookie', pending.cookie).expect(401);
      await http().post('/auth/mfa/replace').set('Cookie', pending.cookie).expect(401);

      await http().post('/auth/mfa/enroll').set('Authorization', `Bearer ${verifiedAccess}`).expect(409);
      expect((await store.getTotp('u1'))!.secret).toBe(before.secret);
      expect((await login('alice@example.com')).res.body).toEqual({ mfa: 'pending' }); // MFA still on

      const staged = await http().post('/auth/mfa/replace').set('Authorization', `Bearer ${verifiedAccess}`).expect(201);
      expect(staged.body.secret).not.toBe(secret);
      const after = (await store.getTotp('u1'))!;
      expect(after).toMatchObject({ secret: before.secret, confirmed: true }); // current one works until confirmed
      expect(after.pendingSecret).toMatch(/^v1\.[\w-]{8}\./);
    });

    it('accepts a recovery code once', async () => {
      const a = await login('alice@example.com');
      await http().post('/auth/mfa').set('Cookie', a.cookie).send({ recoveryCode: recoveryCodes[0].toLowerCase() }).expect(200);
      const b = await login('alice@example.com');
      await http().post('/auth/mfa').set('Cookie', b.cookie).send({ recoveryCode: recoveryCodes[0] }).expect(401);
    });

    it('lets a pending session sign out', async () => {
      const { cookie } = await login('alice@example.com');
      await http().post('/auth/logout').set('Cookie', cookie).expect(204);
      await http().post('/auth/mfa').set('Cookie', cookie).send({ recoveryCode: recoveryCodes[1] }).expect(401);
    });

    it('@Authenticate({ mfa: true }) refuses sessions and tokens without a verified second factor', async () => {
      const { cookie } = await login('bob@example.com');
      const res = await http().get('/me/sensitive').set('Cookie', cookie).expect(401);
      expect(res.body.error).toBe('mfa_required');
      const { accessToken } = await token('bob@example.com');
      await http().get('/me/sensitive').set('Authorization', `Bearer ${accessToken}`).expect(401);
    });
  });

  describe('magic links', () => {
    /** Requests a link as a browser would: the token from the mail, the transaction cookie from the response. */
    const requestLink = async (email: string, redirectTo?: string) => {
      const res = await http().post('/auth/magic').send({ email, redirectTo }).expect(202);
      expect(res.headers['set-cookie']).toEqual([
        expect.stringMatching(/^__Host-magic_link_tx=[\w-]{12}\.[\w-]{43}; Max-Age=900; Path=\/; HttpOnly; Secure; SameSite=Lax$/),
      ]);
      return { token: new URL(outbox.at(-1)!.url).searchParams.get('token')!, tx: cookieOf(res, '__Host-magic_link_tx') };
    };

    it('sends a link, signs in once through SignInService, and ignores unsafe redirects', async () => {
      const { token: tokenParam, tx } = await requestLink(' Bob@Example.com ', '//evil.test');
      expect(outbox.at(-1)!.email).toBe('bob@example.com');

      const res = await http()
        .post('/auth/magic/consume')
        .set('User-Agent', 'Mail app')
        .set('Cookie', tx)
        .send({ token: tokenParam })
        .expect(200, { redirectTo: '/' });
      expect(res.headers['set-cookie']).toEqual([
        '__Host-magic_link_tx=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax', // the link is settled
        expect.stringMatching(/^sid=[\w-]{43}; /),
      ]);

      const cookie = cookieOf(res);
      const list = await http().get('/auth/sessions').set('Cookie', cookie).expect(200);
      expect(list.body.find((s: { current: boolean }) => s.current).metadata).toEqual({ userAgent: 'Mail app' });

      await http().post('/auth/magic/consume').set('Cookie', tx).send({ token: tokenParam }).expect(401);
    });

    it('refuses a link in any browser but the one that requested it, and keeps it for that one', async () => {
      const seen: AuthenticationEvent[] = [];
      const subscription = app.get(AuthenticationEvents).events$.subscribe((event) => seen.push(event));
      try {
        const mine = await requestLink('bob@example.com');
        const theirs = await requestLink('bob@example.com');

        // No cookie (a forwarded link, another device), or this browser's own cookie for another link:
        // the MagicLinkError escapes the route, and the module answers it, unlike a bad link's 401.
        const bare = await http().post('/auth/magic/consume').send({ token: theirs.token }).expect(401);
        expect(bare.body).toEqual({
          message: 'Open the link in the browser you requested it from, or request a new one here',
          error: 'not_this_browser',
          code: 'not_this_browser',
          statusCode: 401,
        });

        const other = await http().post('/auth/magic/consume').set('Cookie', mine.tx).send({ token: theirs.token }).expect(401);
        expect(other.body.error).toBe('not_this_browser');
        expect(other.headers['set-cookie']).toBeUndefined(); // my cookie stays: my link is still to come

        expect(seen).toEqual([
          { type: 'magic-link-refused', reason: 'not-this-browser' },
          { type: 'magic-link-refused', reason: 'not-this-browser' },
        ]);

        // Neither attempt burned the link: it works where it was requested. So does mine.
        await http().post('/auth/magic/consume').set('Cookie', theirs.tx).send({ token: theirs.token }).expect(200);
        await http().post('/auth/magic/consume').set('Cookie', mine.tx).send({ token: mine.token }).expect(200);
      } finally {
        subscription.unsubscribe();
      }
    });

    it('answers a request without a usable address like any other, and sends nothing', async () => {
      const sent = outbox.length;

      for (const body of [{}, { email: 42 }, { email: null }, { email: ['bob@example.com'] }, { email: '   ' }]) {
        const res = await http().post('/auth/magic').send(body).expect(202);
        expect(res.headers['set-cookie']).toBeUndefined();
      }

      expect(outbox).toHaveLength(sent);
    });

    it('does not sign in unknown addresses', async () => {
      const { token: tokenParam, tx } = await requestLink('stranger@example.com');
      const res = await http().post('/auth/magic/consume').set('Cookie', tx).send({ token: tokenParam }).expect(401);
      expect(res.headers['set-cookie']).toEqual(['__Host-magic_link_tx=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax']);
    });
  });

  describe('AuthenticationContext (AsyncLocalStorage)', () => {
    it('is readable from a service and does not bleed between concurrent requests', async () => {
      const bob = (await login('bob@example.com')).cookie;
      const { accessToken } = await token('bob@example.com');

      const calls = Array.from({ length: 30 }, (_, i) => {
        const who = i % 3;
        let req = http().get(`/me/context?delay=${30 - i}`);

        if (who === 0) {
          req = req.set('Cookie', bob);
        }
        if (who === 1) {
          req = req.set('Authorization', `Bearer ${accessToken}`);
        }
        if (who === 2) {
          req = req.set('x-api-key', 'key-ci');
        }

        return req.then((res) => [['u2', 'u2', 'svc-ci'][who], res.body.id]);
      });

      for (const [expected, actual] of await Promise.all(calls)) {
        expect(actual).toBe(expected);
      }
    });

    it('is empty outside a request; requireUser() throws AuthenticationError; run() opens a scope', () => {
      const ctx: AuthenticationContext = app.get(AuthenticationContext);
      expect(ctx.user).toBeNull();
      expect(() => ctx.requireUser()).toThrow(AuthenticationError);
      const user = { id: 'job', email: 'job@example.com', name: 'Job', roles: [] };
      expect(ctx.run({ user }, () => ctx.requireUser().id)).toBe('job');
    });
  });

  describe('audit events', () => {
    const recorded: AuthenticationEvent[] = [];
    const channelled: unknown[] = [];
    const onChannel = (message: unknown) => channelled.push(message);
    let subscription: { unsubscribe(): void };

    beforeAll(() => {
      subscription = app.get(AuthenticationEvents).events$.subscribe((event) => recorded.push(event));
      subscribe('nestjs:authentication:sign-in', onChannel);
    });
    afterAll(() => {
      subscription.unsubscribe();
      unsubscribe('nestjs:authentication:sign-in', onChannel);
    });
    beforeEach(() => {
      recorded.length = 0;
      channelled.length = 0;
    });

    it('records sign-ins on events$ and on the `nestjs:authentication:sign-in` channel', async () => {
      const { cookie } = await login('bob@example.com', undefined, 'Audit/1');
      const list = await http().get('/auth/sessions').set('Cookie', cookie).expect(200);
      const sessionId = list.body.find((s: { current: boolean }) => s.current).id;
      const event = { type: 'sign-in', userId: 'u2', sessionId, method: 'password', metadata: { userAgent: 'Audit/1' } };
      expect(recorded).toEqual([event]);
      expect(channelled).toEqual([event]);

      const issued = await token('bob@example.com');
      expect(recorded.at(-1)).toEqual({ type: 'sign-in', userId: 'u2', tokenFamilyId: expect.any(String), method: 'password' });
      expect(channelled).toHaveLength(2);

      await http().post('/auth/refresh').send({ refreshToken: issued.refreshToken }).expect(200);
      await http().post('/auth/refresh').send({ refreshToken: issued.refreshToken }).expect(401);
      expect(recorded.at(-1)).toEqual({
        type: 'refresh-token-reused',
        userId: 'u2',
        tokenFamilyId: (recorded[1] as { tokenFamilyId: string }).tokenFamilyId,
      });
    });

    it('records pending sign-ins and refused codes', async () => {
      const { cookie } = await login('alice@example.com'); // enrolled above
      expect(recorded).toEqual([expect.objectContaining({ type: 'sign-in', userId: 'u1', mfa: 'pending' })]);

      await http().post('/auth/mfa').set('Cookie', cookie).send({ code: '000000' }).expect(401);
      expect(recorded.at(-1)).toEqual({
        type: 'mfa-failed',
        userId: 'u1',
        method: 'totp',
        failures: expect.any(Number), // earlier tests failed codes for Alice too
        locked: false,
      });
    });
  });
});

describe('HTTP/2 (fastify)', () => {
  let app: INestApplication;
  let client: ClientHttp2Session;
  const send = (method: string, path: string, headers: Record<string, string>, body?: object) =>
    new Promise<{ status: number; headers: IncomingHttpHeaders; text: string }>((resolve, reject) => {
      const req = client.request({ ':method': method, ':path': path, ...(body && { 'content-type': 'application/json' }), ...headers });
      let text = '';
      let responseHeaders: IncomingHttpHeaders = {};

      req.on('response', (h) => (responseHeaders = h));
      req.on('data', (chunk) => (text += chunk));
      req.on('end', () => resolve({ status: Number(responseHeaders[':status']), headers: responseHeaders, text }));
      req.on('error', reject);
      req.end(body ? JSON.stringify(body) : undefined);
    });

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication(new FastifyAdapter({ http2: true }) as never);
    await app.listen(0, '127.0.0.1');
    client = connect(`http://127.0.0.1:${app.getHttpServer().address().port}`);
  });
  afterAll(async () => {
    client.close();
    await app.close();
  });

  it('uses the session cookie on same-origin writes: browsers name the host in :authority, not Host', async () => {
    const origin = `http://127.0.0.1:${app.getHttpServer().address().port}`;
    const signIn = await send('POST', '/auth/login', { origin }, { email: 'bob@example.com', password: PASSWORDS['bob@example.com'] });
    expect(signIn.status).toBe(200);
    const cookie = ([] as string[]).concat(signIn.headers['set-cookie'] ?? [])[0].split(';')[0];

    expect((await send('POST', '/auth/sessions/revoke-others', { origin, cookie })).status).toBe(204);
    expect((await send('POST', '/auth/sessions/revoke-others', { origin: 'https://evil.test', cookie })).status).toBe(401);
  });
});
