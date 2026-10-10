/**
 * Password reset and email verification over HTTP, on Express and Fastify: the flows, what
 * invalidates a link, `@Authenticate({ verifiedEmail: true })`, the audit events, and the
 * startup checks. Also the sign-out events.
 */
import { setTimeout as sleep } from 'node:timers/promises';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Injectable,
  Logger,
  Module,
  Patch,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  Authenticate,
  AuthenticationEvents,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  EmailVerificationHandler,
  EmailVerificationService,
  MfaService,
  PasswordHasher,
  PasswordResetHandler,
  PasswordResetService,
  Public,
  SessionCookieProvider,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationEvent,
  type EmailVerificationLink,
  type PasswordResetLink,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';

interface Account {
  id: string;
  email: string;
  emailVerified: boolean;
  passwordHash: string | null;
}

let clock = Date.now();
const mails: (PasswordResetLink | EmailVerificationLink)[] = [];
let lookupDelayMs = 0;

@Injectable()
class Accounts {
  readonly rows = new Map<string, Account>();

  constructor(private readonly hasher: PasswordHasher) {}

  async add(id: string, email: string, password: string | null, emailVerified = false) {
    this.rows.set(id, { id, email, emailVerified, passwordHash: password === null ? null : await this.hasher.hash(password) });
  }
  byEmail(email: string) {
    return [...this.rows.values()].find((row) => row.email === email);
  }
  user(id: string) {
    const row = this.rows.get(id);
    return row && { id: row.id, email: row.email, emailVerified: row.emailVerified };
  }
}

@Injectable()
class ResetMailer extends PasswordResetHandler {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('passwordReset', this);
  }
  async findUser(email: string) {
    await sleep(lookupDelayMs); // a slow database: the request must not wait for it
    const row = this.accounts.byEmail(email);
    return row ? { id: row.id, email: row.email, passwordHash: row.passwordHash } : null;
  }
  send(link: PasswordResetLink) {
    mails.push(link);
  }
  updatePassword(userId: string, passwordHash: string) {
    this.accounts.rows.get(userId)!.passwordHash = passwordHash;
  }
}

@Injectable()
class VerificationMailer extends EmailVerificationHandler {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('emailVerification', this);
  }
  send(link: EmailVerificationLink) {
    mails.push(link);
  }
  markVerified(userId: string, email: string) {
    const row = this.accounts.rows.get(userId);
    if (!row || row.email !== email) {
      return false;
    }
    row.emailVerified = true;
    return true;
  }
}

@Injectable()
class SessionAuth extends SessionCookieProvider<{ id: string; email: string; emailVerified: boolean }> {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return this.accounts.user(session.userId);
  }
}

@Controller()
class AccountController {
  constructor(
    private readonly accounts: Accounts,
    private readonly hasher: PasswordHasher,
    private readonly signInService: SignInService,
    private readonly passwordResets: PasswordResetService,
    private readonly verification: EmailVerificationService,
  ) {}

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn(@Body() body: { email: string; password: string }) {
    const row = this.accounts.byEmail(body.email);
    if (!(await this.hasher.verify(body.password, row?.passwordHash)) || !row) {
      throw new UnauthorizedException();
    }
    const { session } = await this.signInService.signIn(row.id, { method: 'password' });
    return { mfaRequired: session.mfa === 'pending' };
  }

  @Public()
  @Post('password/forgot')
  @HttpCode(202)
  forgot(@Body('email') email: string) {
    this.passwordResets.request(email);
  }

  @Public()
  @Post('password/reset')
  @HttpCode(200)
  async reset(@Body() body: { token: string; password: string; signIn?: boolean }) {
    const result = await this.passwordResets.reset(body.token, body.password, { signIn: body.signIn });
    if (!result) {
      throw new BadRequestException('Invalid or expired link');
    }
    return { mfaRequired: result.signedIn?.session.mfa === 'pending', signedIn: !!result.signedIn };
  }

  @Post('email/verification')
  @HttpCode(202)
  async resend(@CurrentUser() user: { id: string; email: string }) {
    await this.verification.send(user);
  }

  @Public()
  @Post('email/verify')
  @HttpCode(200)
  async verify(@Body('token') token: string) {
    const verified = await this.verification.verify(token);
    if (!verified) {
      throw new BadRequestException('Invalid or expired link');
    }
    return verified;
  }

  @Patch('email')
  changeEmail(@CurrentUser('id') id: string, @Body('email') email: string) {
    const row = this.accounts.rows.get(id)!;
    Object.assign(row, { email, emailVerified: false });
    return this.accounts.user(id);
  }

  @Authenticate({ verifiedEmail: true })
  @Get('orders')
  orders() {
    return [];
  }

  @Authenticate({ verifiedEmail: true, optional: true })
  @Get('catalog')
  catalog(@CurrentUser() user: unknown) {
    return { user };
  }
}

@Module({ providers: [Accounts], exports: [Accounts] })
class AccountsModule {}

@Module({ imports: [AccountsModule], providers: [ResetMailer] })
class ResetModule {}

@Module({ imports: [AccountsModule], providers: [VerificationMailer] })
class VerificationModule {}

@Module({
  imports: [
    AccountsModule,
    ResetModule,
    VerificationModule,
    AuthenticationModule.forRoot({
      session: { cookie: { secure: false } },
      password: { logN: 10 },
      mfa: { encryption: false, now: () => clock },
      accessToken: { key: 'test-secret-that-is-at-least-32-bytes-long!' },
      passwordReset: { url: 'https://app.test/reset-password', now: () => clock },
      emailVerification: { url: 'https://app.test/verify-email', now: () => clock },
    }),
  ],
  controllers: [AccountController],
  providers: [SessionAuth],
})
class AppModule {}

const cookieOf = (res: request.Response) =>
  ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith('sid='))?.split(';')[0];
const tokenOf = (link: { url: string }) => new URL(link.url).searchParams.get('token')!;

describe.each(adapters.map((a) => a.name))('password reset and email verification (%s)', (adapter) => {
  let app: Awaited<ReturnType<typeof createApp>>;
  let accounts: Accounts;
  let resets: PasswordResetService;
  const seen: AuthenticationEvent[] = [];
  const http = () => request(app.getHttpServer());
  let n = 0;

  beforeAll(async () => {
    app = await createApp(adapter, AppModule);
    accounts = app.get(Accounts);
    resets = app.get(PasswordResetService);
    app.get(AuthenticationEvents).events$.subscribe((event) => seen.push(event));
  });
  afterAll(() => app.close());
  beforeEach(() => {
    mails.length = 0;
    seen.length = 0;
    lookupDelayMs = 0;
    clock = Date.now();
  });

  /** A new account (unverified unless said otherwise) with the password `old password`. */
  async function account(emailVerified = false) {
    const id = `u${++n}`;
    await accounts.add(id, `reader${n}@example.com`, 'old password', emailVerified);
    return accounts.rows.get(id)!;
  }
  const signIn = async (email: string, password = 'old password') =>
    cookieOf(await http().post('/sign-in').send({ email, password }).expect(200))!;
  /** Waits for the reset requests the app is still handling. */
  const settled = () => resets.onModuleDestroy();
  const resetLink = async (email: string) => {
    await http().post('/password/forgot').send({ email }).expect(202);
    await settled();
    return mails.at(-1) as PasswordResetLink;
  };

  describe('password reset', () => {
    it('answers every address the same way, before looking it up', async () => {
      const ada = await account();
      lookupDelayMs = 300;

      const started = performance.now();
      const known = await http().post('/password/forgot').send({ email: ` ${ada.email.toUpperCase()} ` });
      const unknown = await http().post('/password/forgot').send({ email: 'nobody@example.com' });

      expect(performance.now() - started).toBeLessThan(300); // neither waited for the lookup
      expect([known.status, known.text]).toEqual([202, '']);
      expect([unknown.status, unknown.text]).toEqual([202, '']);
      expect(mails).toEqual([]);

      await settled();
      expect(mails).toEqual([{ userId: ada.id, email: ada.email, url: expect.stringMatching(/^https:\/\/app\.test\/reset-password\?token=[\w-]{43}$/), expiresAt: new Date(clock + 3_600_000) }]);
      expect(seen).toEqual([
        { type: 'password-reset-requested', email: ada.email, userId: ada.id },
        { type: 'password-reset-requested', email: 'nobody@example.com' },
      ]);
    });

    it('sets the new password once, and signs out every session and token client', async () => {
      const ada = await account();
      const laptop = await signIn(ada.email);
      const phone = await signIn(ada.email);
      const tokens = await app.get(TokenService).issue(ada.id);
      const link = await resetLink(ada.email);
      seen.length = 0;

      const done = await http().post('/password/reset').send({ token: tokenOf(link), password: 'new password' }).expect(200);
      expect(done.body).toEqual({ mfaRequired: false, signedIn: false });
      expect(cookieOf(done)).toBeUndefined();

      for (const cookie of [laptop, phone]) {
        await http().get('/orders').set('Cookie', cookie).expect(401);
      }
      await expect(app.get(TokenService).refresh(tokens.refreshToken)).rejects.toMatchObject({ reason: 'invalid' });

      await http().post('/sign-in').send({ email: ada.email, password: 'old password' }).expect(401);
      await signIn(ada.email, 'new password');
      expect(seen[0]).toEqual({ type: 'password-reset', userId: ada.id });

      const again = await http().post('/password/reset').send({ token: tokenOf(link), password: 'other password' }).expect(400);
      expect(again.body).toEqual({ message: 'Invalid or expired link', error: 'Bad Request', statusCode: 400 });
    });

    it('works for one of several links, and burns the others', async () => {
      const ada = await account();
      const first = await resetLink(ada.email);
      const second = await resetLink(ada.email);
      await http().post('/password/reset').send({ token: tokenOf(second), password: 'new password' }).expect(200);
      await http().post('/password/reset').send({ token: tokenOf(first), password: 'other password' }).expect(400);
    });

    it('refuses a link once the password or the address changed, or once it expired', async () => {
      const ada = await account();
      const beforeChange = await resetLink(ada.email);
      ada.passwordHash = await app.get(PasswordHasher).hash('changed elsewhere'); // e.g. a "change password" page
      await http().post('/password/reset').send({ token: tokenOf(beforeChange), password: 'new password' }).expect(400);

      const beforeMove = await resetLink(ada.email);
      ada.email = `moved.${ada.email}`;
      await http().post('/password/reset').send({ token: tokenOf(beforeMove), password: 'new password' }).expect(400);

      const expiring = await resetLink(ada.email);
      clock += 3_600_000;
      await http().post('/password/reset').send({ token: tokenOf(expiring), password: 'new password' }).expect(400);
      expect(await app.get(PasswordHasher).verify('changed elsewhere', ada.passwordHash)).toBe(true);

      for (const token of ['', 'x'.repeat(43), '../../etc/passwd', 42]) {
        await http().post('/password/reset').send({ token, password: 'new password' }).expect(400);
      }
    });

    it('signs in on request (pending for a user with an authenticator), and verifies the address', async () => {
      const ada = await account();
      const mfa = app.get(MfaService);
      const { secret } = await mfa.enroll(ada.id, ada.email);
      await mfa.confirm(ada.id, hotp(base32Decode(secret), Math.floor(clock / 30_000)));
      seen.length = 0;

      const link = await resetLink(ada.email);
      const done = await http().post('/password/reset').send({ token: tokenOf(link), password: 'new password', signIn: true }).expect(200);
      expect(done.body).toEqual({ mfaRequired: true, signedIn: true });

      const cookie = cookieOf(done)!;
      expect(cookie).toMatch(/^sid=[\w-]{43}$/);
      await http().get('/orders').set('Cookie', cookie).expect(401); // pending: the second factor comes next

      expect(ada.emailVerified).toBe(true);
      expect(seen.map((e) => e.type)).toEqual(['password-reset-requested', 'password-reset', 'sign-in']);
    });

    it('refuses a sign-in from another origin before it spends the link, and keeps the password', async () => {
      const ada = await account();
      const token = tokenOf(await resetLink(ada.email));
      const send = { token, password: 'new password', signIn: true };

      await http().post('/password/reset').set('Origin', 'https://evil.test').send(send).expect(403);
      expect(await app.get(PasswordHasher).verify('old password', ada.passwordHash)).toBe(true);

      await http().post('/password/reset').send(send).expect(200); // the same link, from a client without an Origin
      expect(await app.get(PasswordHasher).verify('new password', ada.passwordHash)).toBe(true);
    });

    it('logs a failed delivery instead of failing the request', async () => {
      const ada = await account();
      const failing = vi.spyOn(ResetMailer.prototype, 'send').mockRejectedValueOnce(new Error('SMTP down'));
      const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});

      await http().post('/password/forgot').send({ email: ada.email }).expect(202);
      await settled();

      expect(logged).toHaveBeenCalledWith('A password reset request failed', expect.stringContaining('SMTP down'));
      failing.mockRestore();
      logged.mockRestore();
    });
  });

  describe('email verification', () => {
    it('@Authenticate({ verifiedEmail: true }) refuses an unverified address with 403 until the link is used', async () => {
      const ada = await account();
      const cookie = await signIn(ada.email);

      const refused = await http().get('/orders').set('Cookie', cookie).expect(403);
      expect(refused.body).toEqual({ message: 'Email address not verified', error: 'email_unverified', errorCode: 'email_unverified', statusCode: 403 });
      await http().get('/catalog').expect(200, { user: null }); // anonymous callers of an optional route pass
      await http().get('/catalog').set('Cookie', cookie).expect(403);

      await http().post('/email/verification').set('Cookie', cookie).expect(202);
      const link = mails.at(-1) as EmailVerificationLink;
      expect(link).toEqual({ userId: ada.id, email: ada.email, url: expect.stringMatching(/^https:\/\/app\.test\/verify-email\?token=[\w-]{43}$/), expiresAt: new Date(clock + 86_400_000) });

      const verified = await http().post('/email/verify').send({ token: tokenOf(link) }).expect(200);
      expect(verified.body).toEqual({ userId: ada.id, email: ada.email });
      await http().get('/orders').set('Cookie', cookie).expect(200, []);
      expect(seen.filter((e) => e.type === 'email-verified')).toEqual([{ type: 'email-verified', userId: ada.id, email: ada.email }]);

      await http().post('/email/verify').send({ token: tokenOf(link) }).expect(400); // once
    });

    it('a link verifies only the address it was sent to', async () => {
      const ada = await account();
      const cookie = await signIn(ada.email);
      await http().post('/email/verification').set('Cookie', cookie).expect(202);
      const oldLink = mails.at(-1)!;

      await http().patch('/email').set('Cookie', cookie).send({ email: `new.${ada.email}` }).expect(200);
      await http().post('/email/verify').send({ token: tokenOf(oldLink) }).expect(400);
      expect(ada.emailVerified).toBe(false);

      await http().post('/email/verification').set('Cookie', cookie).expect(202);
      const newLink = mails.at(-1)!;
      expect(newLink.email).toBe(ada.email);

      clock += 86_400_000; // expired
      await http().post('/email/verify').send({ token: tokenOf(newLink) }).expect(400);
      expect(ada.emailVerified).toBe(false);
    });

    it('asks the handler, when it overrides isVerified()', async () => {
      const ada = await account(true);
      const cookie = await signIn(ada.email);
      await http().get('/orders').set('Cookie', cookie).expect(200);

      const spy = vi.spyOn(VerificationMailer.prototype, 'isVerified').mockResolvedValueOnce(false);
      await http().get('/orders').set('Cookie', cookie).expect(403);
      expect(spy).toHaveBeenCalledWith({ id: ada.id, email: ada.email, emailVerified: true });
      spy.mockRestore();
    });
  });

  it('publishes sign-out events', async () => {
    const ada = await account();
    const cookie = await signIn(ada.email);

    const sessionId = (await app.get(SessionService).list(ada.id))[0]!.id;
    await app.get(SessionService).revoke(sessionId, { userId: ada.id });

    const pair = await app.get(TokenService).issue(ada.id);
    await app.get(TokenService).revoke(pair.refreshToken);

    await app.get(SignInService).signOutEverywhere(ada.id);

    expect(cookie).toBeDefined();
    expect(seen.filter((e) => e.type === 'sign-out')).toEqual([
      { type: 'sign-out', userId: ada.id, sessionId },
      { type: 'sign-out', userId: ada.id, tokenFamilyId: expect.any(String) },
      { type: 'sign-out', userId: ada.id, everywhere: true },
    ]);
  });
});

describe('password reset and email verification: startup', () => {
  const start = async (options: Parameters<typeof AuthenticationModule.forRoot>[0], handlers: (typeof ResetModule)[] = []) => {
    const moduleRef = await Test.createTestingModule({ imports: [AccountsModule, ...handlers, AuthenticationModule.forRoot(options)] }).compile();
    return moduleRef.init();
  };

  it('fails, naming what is missing, when a feature has its option without its handler, or the reverse', async () => {
    await expect(start({ passwordReset: { url: 'https://app.test/r' } })).rejects.toThrow(
      "AuthenticationModule: `passwordReset` is configured, but no PasswordResetHandler is registered. Write an @Injectable() class that extends PasswordResetHandler, provide it in one of your modules, and register it from its constructor: `registry.registerHandler('passwordReset', this)`",
    );
    await expect(start({ emailVerification: { url: 'https://app.test/v' } })).rejects.toThrow(/no EmailVerificationHandler is registered/);

    await expect(start({}, [ResetModule])).rejects.toThrow(
      'AuthenticationModule: ResetMailer is registered as the `passwordReset` handler, but the `passwordReset` option is missing. ' +
        "Configure it in the AuthenticationModule options: `passwordReset: { url: 'https://app.example.com/reset-password' }`.",
    );
    await expect(start({}, [VerificationModule])).rejects.toThrow(/`emailVerification` option is missing/);

    await expect(start({ passwordReset: {} as never }, [ResetModule])).rejects.toThrow(/`passwordReset.url` is required/);
    await expect(start({ passwordReset: { url: 'https://app.test/r', ttl: 'soon' as never } }, [ResetModule])).rejects.toThrow(/Invalid duration "soon"/);
  });

  it('refuses to start in production with the links in memory', async () => {
    const env = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      await expect(start({ emailVerification: { url: 'https://app.test/v' } }, [VerificationModule])).rejects.toThrow(
        'no store is registered for `emailTokens` (EmailTokenStore), and NODE_ENV is "production": in memory, password reset and verification links would be lost',
      );
    } finally {
      process.env.NODE_ENV = env;
    }
  });
});
