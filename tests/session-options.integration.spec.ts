/**
 * The `session` options as a browser meets them, on Express and Fastify: the cookie's name
 * and attributes, absolute and idle expiry and `touchInterval` on the configured clock,
 * `mfa.pendingTtl`, and `trustedOrigins` for writes and sign-ins from another origin.
 */
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Body, Controller, Get, HttpCode, Injectable, Module, Post, UnauthorizedException, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  Authenticate,
  AuthenticationModule,
  AuthenticationRegistry,
  AuthenticationStorage,
  CurrentUser,
  MfaService,
  Public,
  SessionCookieProvider,
  SignInService,
  type AuthenticationModuleOptions,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';

const MINUTE = 60_000;
const TRUSTED = 'https://app.example.com';
let clock = Date.UTC(2026, 0, 1);

const sha256 = (value: string) => createHash('sha256').update(value).digest('base64url');
const setCookies = (res: request.Response) => ([] as string[]).concat(res.headers['set-cookie'] ?? []);
const cookieNamed = (res: request.Response, name: string) => setCookies(res).find((c) => c.startsWith(`${name}=`));
const pairOf = (setCookie: string) => setCookie.split(';')[0];
const attributesOf = (setCookie: string) =>
  setCookie
    .split(';')
    .slice(1)
    .map((part) => part.trim().toLowerCase())
    .sort();

@Injectable()
class People extends SessionCookieProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return { id: session.userId };
  }
}

@Controller()
class AppController {
  constructor(
    private readonly signInService: SignInService,
    private readonly mfaService: MfaService,
  ) {}

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn(@Body('userId') userId: string) {
    const { session } = await this.signInService.signIn(userId, { method: 'password' });
    return { mfa: session.mfa ?? null };
  }

  @Public()
  @Post('mfa')
  @HttpCode(200)
  async completeMfa(@Body('code') code: string) {
    if (!(await this.signInService.completeMfa({ code }))) {
      throw new UnauthorizedException();
    }
    return { ok: true };
  }

  @Get('me')
  me(@CurrentUser('id') id: string) {
    return { id };
  }

  @Authenticate({ optional: true })
  @Get('feed')
  feed(@CurrentUser() user: { id: string } | null) {
    return { user: user?.id ?? null };
  }

  @Post('notes')
  note(@CurrentUser('id') id: string) {
    return { by: id };
  }

  // Test support: an authenticator for a user, enrolled and confirmed on the app's clock.
  @Public()
  @Post('test/enroll')
  async enroll(@Body('userId') userId: string) {
    const { secret } = await this.mfaService.enroll(userId, `${userId}@example.com`);
    await this.mfaService.confirm(userId, hotp(base32Decode(secret), Math.floor(clock / 30_000)));
    return { secret };
  }
}

function appModule(options: AuthenticationModuleOptions) {
  @Module({
    imports: [AuthenticationModule.forRoot(options)],
    controllers: [AppController],
    providers: [People],
  })
  class SessionAppModule {}
  return SessionAppModule;
}

const defaults = appModule({
  session: { absoluteTtl: '2h', idleTtl: '30m', touchInterval: '5m', trustedOrigins: [TRUSTED], now: () => clock },
  mfa: { encryption: false, pendingTtl: '5m', now: () => clock },
});

describe.each(adapters.map((a) => a.name))('session options (%s)', (adapter) => {
  describe('the defaults, with trusted origins and a clock', () => {
    let app: INestApplication;
    let n = 0;
    const http = () => request(app.getHttpServer());

    beforeAll(async () => {
      app = await createApp(adapter, defaults);
    });
    afterAll(() => app.close());

    async function signIn(headers: Record<string, string> = {}) {
      const userId = `user-${++n}`;
      const res = await http().post('/sign-in').set(headers).send({ userId }).expect(200);
      const setCookie = cookieNamed(res, '__Host-sid')!;
      return { userId, setCookie, cookie: pairOf(setCookie), res };
    }
    const session = (cookie: string) => app.get(AuthenticationStorage).sessions.getSession(sha256(cookie.split('=')[1]));

    it('sets __Host-sid: HttpOnly, Secure, SameSite=Lax at Path=/ without a Domain, for the absolute lifetime', async () => {
      const { setCookie, cookie } = await signIn();

      expect(cookie).toMatch(/^__Host-sid=[\w-]{43}$/);
      expect(attributesOf(setCookie)).toEqual(['httponly', 'max-age=7200', 'path=/', 'samesite=lax', 'secure']);
    });

    it('slides the idle timeout with activity, writing lastActiveAt at most once per touchInterval', async () => {
      const { cookie, userId } = await signIn();
      const signedInAt = clock;

      clock += 3 * MINUTE;
      await http().get('/me').set('Cookie', cookie).expect(200, { id: userId });
      expect((await session(cookie))!.lastActiveAt.getTime()).toBe(signedInAt);

      clock += 3 * MINUTE;
      await http().get('/me').set('Cookie', cookie).expect(200);
      expect((await session(cookie))!.lastActiveAt.getTime()).toBe(clock);

      clock += 29 * MINUTE;
      await http().get('/me').set('Cookie', cookie).expect(200);

      clock += 31 * MINUTE;
      await http().get('/me').set('Cookie', cookie).expect(401);
      await http().get('/feed').set('Cookie', cookie).expect(200, { user: null });
      // Idle, but kept: another instance may have touched it since. The store prunes by absolute expiry.
      expect(await session(cookie)).toBeDefined();
    });

    it('ends a session at its absolute expiry however active it is, and deletes it', async () => {
      const { cookie } = await signIn();

      for (let step = 0; step < 5; step++) {
        clock += 20 * MINUTE;
        await http().get('/me').set('Cookie', cookie).expect(200);
      }
      clock += 19 * MINUTE;
      await http().get('/me').set('Cookie', cookie).expect(200);
      clock += MINUTE;

      await http().get('/me').set('Cookie', cookie).expect(401);
      expect(await session(cookie)).toBeUndefined();
    });

    it('gives a pending sign-in mfa.pendingTtl, in the cookie and in the store, and the full lifetime once verified', async () => {
      const userId = `mfa-user-${++n}`;
      const { secret } = (await http().post('/test/enroll').send({ userId }).expect(201)).body;

      clock += 30_000;
      const res = await http().post('/sign-in').send({ userId }).expect(200, { mfa: 'pending' });
      const pending = cookieNamed(res, '__Host-sid')!;
      expect(attributesOf(pending)).toContain('max-age=300');
      expect((await session(pairOf(pending)))!.expiresAt.getTime()).toBe(clock + 5 * MINUTE);

      clock += 5 * MINUTE;
      const expired = await http().post('/mfa').set('Cookie', pairOf(pending)).send({ code: hotp(base32Decode(secret), Math.floor(clock / 30_000)) });
      expect(expired.status).toBe(401);

      const again = cookieNamed(await http().post('/sign-in').send({ userId }).expect(200), '__Host-sid')!;
      clock += MINUTE;
      const verified = await http()
        .post('/mfa')
        .set('Cookie', pairOf(again))
        .send({ code: hotp(base32Decode(secret), Math.floor(clock / 30_000)) })
        .expect(200);
      // The full lifetime, counted from the sign-in a minute ago.
      expect(attributesOf(cookieNamed(verified, '__Host-sid')!)).toContain('max-age=7140');
      await http().get('/me').set('Cookie', pairOf(cookieNamed(verified, '__Host-sid')!)).expect(200, { id: userId });
    });

    it('uses the cookie on writes from the app’s own origin and trusted ones, and ignores it on others', async () => {
      const { cookie, userId } = await signIn();
      const own = `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
      const write = (headers: Record<string, string>) => http().post('/notes').set('Cookie', cookie).set(headers);

      await write({}).expect(201, { by: userId }); // no Origin: not a browser
      await write({ Origin: own }).expect(201);
      await write({ 'Sec-Fetch-Site': 'same-origin', Origin: 'https://evil.test' }).expect(201);
      await write({ Origin: TRUSTED }).expect(201);
      await write({ 'Sec-Fetch-Site': 'cross-site', Origin: TRUSTED }).expect(201);

      const refused = await write({ Origin: 'https://evil.test' }).expect(401);
      expect(refused.body).toEqual({ message: 'Unauthorized', statusCode: 401, errorCode: 'missing_credentials' });
      await write({ 'Sec-Fetch-Site': 'cross-site', Origin: 'https://evil.test' }).expect(401);
      await write({ 'Sec-Fetch-Site': 'same-site', Origin: 'https://sub.app.example.com' }).expect(401);

      // Reads are safe: a link from another site still shows the signed-in page.
      await http().get('/me').set('Cookie', cookie).set('Origin', 'https://evil.test').expect(200);
    });

    it('signs the browser in from a trusted origin, and refuses every other origin with a 403', async () => {
      const trusted = await signIn({ Origin: TRUSTED });
      await http().get('/me').set('Cookie', trusted.cookie).expect(200, { id: trusted.userId });

      const refused = await http().post('/sign-in').set('Origin', 'https://evil.test').send({ userId: 'victim' }).expect(403);
      expect(setCookies(refused)).toEqual([]);
    });
  });

  describe('a custom cookie', () => {
    let app: INestApplication;

    beforeAll(async () => {
      app = await createApp(
        adapter,
        appModule({ session: { cookieName: 'app_session', absoluteTtl: '1d', cookie: { domain: 'app.test', sameSite: 'strict' } } }),
      );
    });
    afterAll(() => app.close());

    it('takes the configured name and attributes, and reads the cookie back by that name', async () => {
      const res = await request(app.getHttpServer()).post('/sign-in').send({ userId: 'u1' }).expect(200);
      const setCookie = cookieNamed(res, 'app_session')!;

      expect(attributesOf(setCookie)).toEqual(['domain=app.test', 'httponly', 'max-age=86400', 'path=/', 'samesite=strict', 'secure']);
      await request(app.getHttpServer()).get('/me').set('Cookie', pairOf(setCookie)).expect(200, { id: 'u1' });
      await request(app.getHttpServer()).get('/me').set('Cookie', `sid=${pairOf(setCookie).split('=')[1]}`).expect(401);
    });

    it('is plain sid when a Domain rules the __Host- prefix out', async () => {
      const plain = await createApp(adapter, appModule({ session: { cookie: { domain: 'app.test' } } }));
      const res = await request(plain.getHttpServer()).post('/sign-in').send({ userId: 'u1' }).expect(200);

      expect(cookieNamed(res, 'sid')).toMatch(/Domain=app\.test/i);
      expect(cookieNamed(res, '__Host-sid')).toBeUndefined();
      await plain.close();
    });
  });
});

describe('cookies browsers would drop fail at startup', () => {
  it.each([
    [{ cookieName: '__Host-session', cookie: { domain: 'app.test' } }, /__Host-/],
    [{ cookie: { sameSite: 'none' as const, secure: false } }, /SameSite=None/i],
  ])('%o', async (session, message) => {
    const moduleRef = await Test.createTestingModule({ imports: [appModule({ session })] }).compile().catch((error: Error) => error);
    const failure = moduleRef instanceof Error ? moduleRef : await moduleRef.createNestApplication().init().catch((error: Error) => error);

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toMatch(message);
  });
});
