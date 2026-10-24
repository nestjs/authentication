/**
 * The audit trail as an operator subscribes to it, on Express and Fastify: one user's story
 * over HTTP (password, second factor, tokens, links, sign-outs), every step checked against
 * `AuthenticationEvents.events$` and against the `nestjs:authentication:<type>` diagnostics
 * channels, which carry the same payloads in the same order. On shutdown, `events$`
 * completes.
 */
import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  HttpCode,
  Injectable,
  Module,
  NotFoundException,
  Param,
  Post,
  UnauthorizedException,
  type INestApplication,
} from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  Authenticate,
  AuthenticationEvents,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentSession,
  CurrentUser,
  EmailVerificationHandler,
  EmailVerificationService,
  MagicLinkHandler,
  MagicLinkService,
  MfaService,
  PasswordResetHandler,
  PasswordResetService,
  Public,
  SessionCookieProvider,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationEvent,
  type EmailVerificationLink,
  type MagicLink,
  type PasswordResetLink,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';

const TYPES: AuthenticationEvent['type'][] = [
  'sign-in',
  'sign-out',
  'mfa-verified',
  'mfa-failed',
  'mfa-enabled',
  'mfa-disabled',
  'recovery-codes-generated',
  'refresh-token-reused',
  'password-reset-requested',
  'password-reset',
  'email-verified',
  'magic-link-refused',
];

const links: (MagicLink | PasswordResetLink | EmailVerificationLink)[] = [];
// The app's TOTP clock (`mfa.now`), fixed when the file loads: on the wall clock the 30-second step
// can turn between making a code and the app checking it, and the previous step's code is then refused.
const clock = Date.now();
const totp = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(clock / 30_000) + offset);
const tokenOf = (link: { url: string }) => new URL(link.url).searchParams.get('token')!;
const cookieOf = (res: request.Response, name = '__Host-sid') =>
  ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith(`${name}=`))?.split(';')[0];

@Injectable()
class Accounts {
  readonly hashes = new Map<string, string | null>();
  readonly emails = new Map<string, string>();
}

@Injectable()
class SessionAuth extends SessionCookieProvider<{ id: string; email: string }> {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return { id: session.userId, email: this.accounts.emails.get(session.userId)! };
  }
}

@Injectable()
class Handlers extends MagicLinkHandler {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerHandler('magicLink', this);
  }
  send(link: MagicLink) {
    links.push(link);
  }
  resolveUser(email: string) {
    return { id: email.split('@')[0], email };
  }
}

@Injectable()
class ResetHandler extends PasswordResetHandler {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('passwordReset', this);
  }
  findUser(email: string) {
    const id = email.split('@')[0];
    return this.accounts.emails.has(id) ? { id, email, passwordHash: this.accounts.hashes.get(id) ?? null } : null;
  }
  send(link: PasswordResetLink) {
    links.push(link);
  }
  updatePassword(userId: string, passwordHash: string) {
    this.accounts.hashes.set(userId, passwordHash);
  }
}

@Injectable()
class VerificationHandler extends EmailVerificationHandler {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerHandler('emailVerification', this);
  }
  send(link: EmailVerificationLink) {
    links.push(link);
  }
  markVerified() {
    return true;
  }
}

@Controller()
class JourneyController {
  constructor(
    private readonly accounts: Accounts,
    private readonly signInService: SignInService,
    private readonly sessionService: SessionService,
    private readonly mfaService: MfaService,
    private readonly tokenService: TokenService,
    private readonly magicLinkService: MagicLinkService,
    private readonly passwordResetService: PasswordResetService,
    private readonly emailVerificationService: EmailVerificationService,
  ) {}

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn(@Body('userId') userId: string) {
    this.accounts.emails.set(userId, `${userId}@example.com`);
    await this.signInService.signIn(userId, { method: 'password' });
  }

  @Public()
  @Post('mfa/complete')
  @HttpCode(200)
  async complete(@Body() body: { code?: string; recoveryCode?: string }) {
    if (!(await this.signInService.completeMfa(body))) {
      throw new UnauthorizedException();
    }
  }

  @Post('mfa/enroll')
  enroll(@CurrentUser() user: { id: string; email: string }) {
    return this.mfaService.enroll(user.id, user.email);
  }

  @Post('mfa/confirm')
  @HttpCode(200)
  async confirm(@CurrentUser('id') userId: string, @Body('code') code: string) {
    if (!(await this.signInService.confirmMfa(userId, code))) {
      throw new UnauthorizedException();
    }
    return { recoveryCodes: await this.mfaService.generateRecoveryCodes(userId) };
  }

  @Authenticate({ mfa: true })
  @Delete('mfa')
  @HttpCode(204)
  disable(@CurrentUser('id') userId: string) {
    return this.mfaService.disable(userId);
  }

  @Public()
  @Post('token')
  @HttpCode(200)
  token(@Body() body: { userId: string; code?: string; recoveryCode?: string }) {
    return this.tokenService.issue(body.userId, { method: 'password', secondFactor: { code: body.code, recoveryCode: body.recoveryCode } });
  }

  @Public()
  @Post('token/refresh')
  @HttpCode(200)
  refresh(@Body('refreshToken') refreshToken: string) {
    return this.tokenService.refresh(refreshToken);
  }

  @Public()
  @Post('token/revoke')
  @HttpCode(204)
  async revokeToken(@Body('refreshToken') refreshToken: string) {
    await this.tokenService.revoke(refreshToken);
  }

  @Delete('sessions/:id')
  @HttpCode(204)
  async revokeSession(@CurrentUser('id') userId: string, @Param('id') id: string) {
    if (!(await this.sessionService.revoke(id, { userId }))) {
      throw new NotFoundException();
    }
  }

  @Post('sessions/current')
  @HttpCode(200)
  current(@CurrentSession() session: SessionRecord) {
    return { id: session.id };
  }

  @Public()
  @Post('sign-out')
  @HttpCode(204)
  async signOut() {
    await this.signInService.signOut();
  }

  @Post('sign-out-everywhere')
  @HttpCode(204)
  async signOutEverywhere(@CurrentUser('id') userId: string) {
    await this.signInService.signOutEverywhere(userId);
  }

  @Public()
  @Post('magic')
  @HttpCode(202)
  async magic(@Body('email') email: string) {
    await this.magicLinkService.create(email);
  }

  @Public()
  @Post('magic/consume')
  @HttpCode(200)
  async consume(@Body('token') token: string) {
    return { signedIn: !!(await this.magicLinkService.consume(token)) };
  }

  @Post('email/verification')
  @HttpCode(202)
  async sendVerification(@CurrentUser() user: { id: string; email: string }) {
    await this.emailVerificationService.send(user);
  }

  @Public()
  @Post('email/verify')
  @HttpCode(200)
  async verify(@Body('token') token: string) {
    if (!(await this.emailVerificationService.verify(token))) {
      throw new BadRequestException();
    }
  }

  @Public()
  @Post('password/forgot')
  @HttpCode(202)
  forgot(@Body('email') email: string) {
    this.passwordResetService.request(email);
  }

  @Public()
  @Post('password/reset')
  @HttpCode(200)
  async reset(@Body() body: { token: string; password: string }) {
    if (!(await this.passwordResetService.reset(body.token, body.password))) {
      throw new BadRequestException();
    }
  }
}

@Module({
  imports: [
    AuthenticationModule.forRoot({
      session: { metadata: ({ headers }) => ({ userAgent: headers['user-agent'] ?? null }) },
      password: { logN: 10 },
      mfa: { encryption: false, now: () => clock },
      accessToken: { key: 'audit-test-secret-of-at-least-32-bytes-long' },
      magicLink: { url: 'https://app.test/magic' },
      passwordReset: { url: 'https://app.test/reset-password' },
      emailVerification: { url: 'https://app.test/verify-email' },
    }),
  ],
  controllers: [JourneyController],
  providers: [Accounts, SessionAuth, Handlers, ResetHandler, VerificationHandler],
})
class AuditAppModule {}

describe.each(adapters.map((a) => a.name))('the audit trail (%s)', (adapter) => {
  let app: INestApplication;
  const fromStream: AuthenticationEvent[] = [];
  const fromChannels: AuthenticationEvent[] = [];
  const onChannel = (message: unknown) => {
    fromChannels.push(message as AuthenticationEvent);
  };
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    app = await createApp(adapter, AuditAppModule);
    app.get(AuthenticationEvents).events$.subscribe((event) => fromStream.push(event));
    for (const type of TYPES) {
      subscribe(`nestjs:authentication:${type}`, onChannel);
    }
  });
  afterAll(async () => {
    for (const type of TYPES) {
      unsubscribe(`nestjs:authentication:${type}`, onChannel);
    }
    await app?.close();
  });

  /** The events one step published, the same on both. */
  async function step(action: () => Promise<unknown>) {
    const mark = fromStream.length;
    const channelMark = fromChannels.length;
    await action();
    const published = fromStream.slice(mark);
    expect(fromChannels.slice(channelMark)).toEqual(published);
    return published;
  }

  it('records one user’s story, step by step, on events$ and on the channels', async () => {
    const userId = `${adapter}-ada`;
    const email = `${userId}@example.com`;
    let cookie = '';

    // Password sign-in.
    expect(
      await step(async () => {
        cookie = cookieOf(await http().post('/sign-in').set('User-Agent', 'laptop').send({ userId }).expect(200))!;
      }),
    ).toEqual([{ type: 'sign-in', userId, sessionId: expect.any(String), method: 'password', metadata: { userAgent: 'laptop' } }]);

    // Enrolling an authenticator, and the recovery codes shown with it.
    let secret = '';
    let recoveryCodes: string[] = [];
    expect(
      await step(async () => {
        secret = (await http().post('/mfa/enroll').set('Cookie', cookie).expect(201)).body.secret;
        const confirmed = await http().post('/mfa/confirm').set('Cookie', cookie).send({ code: totp(secret, -1) }).expect(200);
        recoveryCodes = confirmed.body.recoveryCodes;
        cookie = cookieOf(confirmed)!;
      }),
    ).toEqual([
      { type: 'mfa-enabled', userId, replaced: false },
      { type: 'recovery-codes-generated', userId, count: 10 },
    ]);

    // A sign-in waiting for its second factor, a wrong code, the right one.
    expect(
      await step(async () => {
        const pending = cookieOf(await http().post('/sign-in').send({ userId }).expect(200))!;
        await http().post('/mfa/complete').set('Cookie', pending).send({ code: '000000' }).expect(401);
        await http().post('/mfa/complete').set('Cookie', pending).send({ code: totp(secret) }).expect(200);
      }),
    ).toEqual([
      { type: 'sign-in', userId, sessionId: expect.any(String), method: 'password', mfa: 'pending', metadata: { userAgent: null } },
      { type: 'mfa-failed', userId, method: 'totp', failures: 1, locked: false },
      { type: 'mfa-verified', userId, method: 'totp' },
    ]);

    // A recovery code.
    expect(
      await step(async () => {
        const pending = cookieOf(await http().post('/sign-in').send({ userId }).expect(200))!;
        await http().post('/mfa/complete').set('Cookie', pending).send({ recoveryCode: recoveryCodes[0] }).expect(200);
      }),
    ).toEqual([
      expect.objectContaining({ type: 'sign-in', mfa: 'pending' }),
      { type: 'mfa-verified', userId, method: 'recovery-code' },
    ]);

    // A token client with the second factor; a refresh token presented twice; a revoked client.
    const tokens = await step(async () => {
      const issued = (await http().post('/token').send({ userId, code: totp(secret, 1) }).expect(200)).body;
      await http().post('/token/refresh').send({ refreshToken: issued.refreshToken }).expect(200);
      await http().post('/token/refresh').send({ refreshToken: issued.refreshToken }).expect(401);
    });
    const familyId = (tokens[1] as { tokenFamilyId: string }).tokenFamilyId;
    expect(tokens).toEqual([
      { type: 'mfa-verified', userId, method: 'totp' },
      { type: 'sign-in', userId, tokenFamilyId: expect.any(String), method: 'password', mfa: 'verified' },
      { type: 'refresh-token-reused', userId, tokenFamilyId: familyId },
    ]);

    expect(
      await step(async () => {
        const issued = (await http().post('/token').send({ userId, recoveryCode: recoveryCodes[1] }).expect(200)).body;
        await http().post('/token/revoke').send({ refreshToken: issued.refreshToken }).expect(204);
      }),
    ).toEqual([
      { type: 'mfa-verified', userId, method: 'recovery-code' },
      expect.objectContaining({ type: 'sign-in', tokenFamilyId: expect.any(String) }),
      { type: 'sign-out', userId, tokenFamilyId: expect.any(String) },
    ]);

    // Switching the second factor off, from a verified session.
    expect(await step(() => http().delete('/mfa').set('Cookie', cookie).expect(204))).toEqual([{ type: 'mfa-disabled', userId }]);

    // Email verification.
    expect(
      await step(async () => {
        await http().post('/email/verification').set('Cookie', cookie).expect(202);
        await http().post('/email/verify').send({ token: tokenOf(links.at(-1)!) }).expect(200);
      }),
    ).toEqual([{ type: 'email-verified', userId, email }]);

    // A magic link opened in another browser, and a malformed one.
    expect(
      await step(async () => {
        await http().post('/magic').send({ email }).expect(202);
        await http().post('/magic/consume').send({ token: tokenOf(links.at(-1)!) }).expect(401);
        await http().post('/magic/consume').send({ token: 'not-a-token' }).expect(200, { signedIn: false });
      }),
    ).toEqual([
      { type: 'magic-link-refused', reason: 'not-this-browser' },
      { type: 'magic-link-refused', reason: 'unknown' },
    ]);

    // One session revoked from a devices page; sign-out; sign-out everywhere.
    expect(
      await step(async () => {
        const phone = cookieOf(await http().post('/sign-in').send({ userId }).expect(200))!;
        const { id } = (await http().post('/sessions/current').set('Cookie', phone).expect(200)).body;
        await http().delete(`/sessions/${id}`).set('Cookie', cookie).expect(204);
      }),
    ).toEqual([expect.objectContaining({ type: 'sign-in' }), { type: 'sign-out', userId, sessionId: expect.any(String) }]);

    expect(
      await step(async () => {
        const tablet = cookieOf(await http().post('/sign-in').send({ userId }).expect(200))!;
        await http().post('/sign-out').set('Cookie', tablet).expect(204);
        await http().post('/sign-out-everywhere').set('Cookie', cookie).expect(204);
      }),
    ).toEqual([
      expect.objectContaining({ type: 'sign-in' }),
      { type: 'sign-out', userId, sessionId: expect.any(String) },
      { type: 'sign-out', userId, everywhere: true },
    ]);

    // A password reset: requested (answered before the lookup), then used.
    expect(
      await step(async () => {
        await http().post('/password/forgot').send({ email }).expect(202);
        await vi.waitFor(() => expect(fromStream.at(-1)?.type).toBe('password-reset-requested'));
        await http().post('/password/reset').send({ token: tokenOf(links.at(-1)!), password: 'new password' }).expect(200);
      }),
    ).toEqual([
      { type: 'password-reset-requested', email, userId },
      { type: 'password-reset', userId },
    ]);

    expect(new Set(fromStream.map((event) => event.type))).toEqual(new Set(TYPES));
  });

  it('reports an unknown address asking for a reset without a userId', async () => {
    const published = await step(async () => {
      await http().post('/password/forgot').send({ email: 'nobody@example.com' }).expect(202);
      await vi.waitFor(() => expect(fromStream.at(-1)).toEqual({ type: 'password-reset-requested', email: 'nobody@example.com' }));
    });

    expect(published).toEqual([{ type: 'password-reset-requested', email: 'nobody@example.com' }]);
  });
});

describe('events$ on shutdown', () => {
  it('completes when the app closes', async () => {
    const app = await createApp('express', AuditAppModule);
    const completed = vi.fn();
    app.get(AuthenticationEvents).events$.subscribe({ complete: completed });

    await app.close();

    expect(completed).toHaveBeenCalledOnce();
  });
});
