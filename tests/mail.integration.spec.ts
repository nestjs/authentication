/**
 * The link features delivered through `@nestjs/mail`, as the README's handlers do it, on
 * Express and Fastify: the app's transport replaced by an `InMemoryMailTransport`, links read
 * from the mailbox and followed over HTTP. Also what the two packages do together when a
 * delivery fails (the mail package retries a transient failure; a permanent one is logged
 * by the authentication package) and on shutdown (a reset requested just before is still
 * delivered).
 */
import { BadRequestException, Body, Controller, Get, HttpCode, Injectable, Logger, Module, Post, UnauthorizedException } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  InMemoryMailTransport,
  LogMailTransport,
  MailModule,
  MailSmtpError,
  MailTransport,
  Mailer,
  html,
  type Mailable,
} from '@nestjs/mail';
import {
  Authenticate,
  AuthenticationEvents,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  EmailVerificationHandler,
  EmailVerificationService,
  MagicLinkHandler,
  MagicLinkService,
  PasswordHasher,
  PasswordResetHandler,
  PasswordResetService,
  Public,
  SessionCookieProvider,
  SignInService,
  type AuthenticationEvent,
  type EmailVerificationLink,
  type MagicLink,
  type PasswordResetLink,
  type SessionRecord,
} from '../lib/index.js';

interface Account {
  id: string;
  email: string;
  emailVerified: boolean;
  passwordHash: string;
}

let lookupGate: Promise<void> | undefined;
let lookupStarted = false;

@Injectable()
class Accounts {
  readonly rows = new Map<string, Account>();

  constructor(private readonly hasher: PasswordHasher) {}

  async create(email: string, password: string) {
    const account = { id: `acct-${this.rows.size + 1}`, email, emailVerified: false, passwordHash: await this.hasher.hash(password) };
    this.rows.set(account.id, account);
    return account;
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
class VerifyEmailMail implements Mailable<EmailVerificationLink> {
  render({ url }: EmailVerificationLink) {
    return { subject: 'Confirm your email address', html: html`<p><a href="${url}">Confirm my address</a></p>` };
  }
}

@Injectable()
class PasswordResetMail implements Mailable<PasswordResetLink> {
  render({ url }: PasswordResetLink) {
    return { subject: 'Reset your password', html: html`<p><a href="${url}">Choose a new password</a></p>` };
  }
}

@Injectable()
class MagicLinkMail implements Mailable<MagicLink> {
  render({ url }: MagicLink) {
    return { subject: 'Your sign-in link', html: html`<p><a href="${url}">Sign in</a></p>` };
  }
}

@Injectable()
class VerificationMailer extends EmailVerificationHandler {
  constructor(
    private readonly accounts: Accounts,
    private readonly mailer: Mailer,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('emailVerification', this);
  }
  async send(link: EmailVerificationLink) {
    await this.mailer.send(VerifyEmailMail, { to: link.email, data: link });
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
class PasswordResetMailer extends PasswordResetHandler {
  constructor(
    private readonly accounts: Accounts,
    private readonly mailer: Mailer,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('passwordReset', this);
  }
  async findUser(email: string) {
    lookupStarted = true;
    await lookupGate;
    const row = this.accounts.byEmail(email);
    return row ? { id: row.id, email: row.email, passwordHash: row.passwordHash } : null;
  }
  async send(link: PasswordResetLink) {
    await this.mailer.send(PasswordResetMail, { to: link.email, data: link });
  }
  updatePassword(userId: string, passwordHash: string) {
    this.accounts.rows.get(userId)!.passwordHash = passwordHash;
  }
}

@Injectable()
class MagicLinkMailer extends MagicLinkHandler {
  constructor(
    private readonly accounts: Accounts,
    private readonly mailer: Mailer,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('magicLink', this);
  }
  async send(link: MagicLink) {
    await this.mailer.send(MagicLinkMail, { to: link.email, data: link });
  }
  resolveUser(email: string) {
    const row = this.accounts.byEmail(email);
    return row?.emailVerified ? this.accounts.user(row.id)! : null;
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
    private readonly emailVerificationService: EmailVerificationService,
    private readonly passwordResetService: PasswordResetService,
    private readonly magicLinkService: MagicLinkService,
  ) {}

  @Public()
  @Post('sign-up')
  async signUp(@Body() body: { email: string; password: string }) {
    const account = await this.accounts.create(body.email, body.password);
    await this.emailVerificationService.send(account);
    await this.signInService.signIn(account.id, { method: 'password' });
    return this.accounts.user(account.id);
  }

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn(@Body() body: { email: string; password: string }) {
    const row = this.accounts.byEmail(body.email);
    if (!(await this.hasher.verify(body.password, row?.passwordHash)) || !row) {
      throw new UnauthorizedException();
    }
    await this.signInService.signIn(row.id, { method: 'password' });
  }

  @Public()
  @Post('verify-email')
  @HttpCode(200)
  async verify(@Body('token') token: string) {
    const verified = await this.emailVerificationService.verify(token);
    if (!verified) {
      throw new BadRequestException('Invalid or expired link');
    }
    return verified;
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
      throw new BadRequestException('Invalid or expired link');
    }
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
    if (!(await this.magicLinkService.consume(token))) {
      throw new UnauthorizedException();
    }
  }

  @Authenticate({ verifiedEmail: true })
  @Get('orders')
  orders(@CurrentUser('email') email: string) {
    return { orders: [], email };
  }
}

@Module({
  imports: [
    MailModule.forRoot({
      transport: new LogMailTransport({ logger: new Logger('Mail', { timestamp: false }) }),
      from: 'Accounts <accounts@example.com>',
      retry: { attempts: 3, backoff: () => 0 },
    }),
    AuthenticationModule.forRoot({
      password: { logN: 10 },
      emailVerification: { url: 'https://example.com/verify-email' },
      passwordReset: { url: 'https://example.com/reset-password' },
      magicLink: { url: 'https://example.com/magic' },
    }),
  ],
  controllers: [AccountController],
  providers: [Accounts, VerifyEmailMail, PasswordResetMail, MagicLinkMail, VerificationMailer, PasswordResetMailer, MagicLinkMailer, SessionAuth],
})
class AppModule {}

const cookieOf = (res: request.Response, name: string) =>
  ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith(`${name}=`))?.split(';')[0];

describe.each(adapters.map((a) => a.name))('links by email through @nestjs/mail (%s)', (adapter) => {
  let app: Awaited<ReturnType<typeof createApp>>;
  let mailbox: InMemoryMailTransport;
  const events: AuthenticationEvent[] = [];
  const http = () => request(app.getHttpServer());
  let n = 0;

  beforeAll(async () => {
    app = await createApp(adapter, AppModule, { override: (builder) => builder.overrideProvider(MailTransport).useValue(new InMemoryMailTransport()) });
    mailbox = app.get(MailTransport);
    app.get(AuthenticationEvents).events$.subscribe((event) => events.push(event));
  });
  afterAll(() => app.close());
  beforeEach(() => {
    lookupGate = undefined;
    events.length = 0;
  });

  async function signUp() {
    const email = `reader${++n}@example.com`;
    const res = await http().post('/sign-up').send({ email, password: 'old password' }).expect(201);
    return { email, cookie: cookieOf(res, '__Host-sid')! };
  }
  const verifyEmail = async (email: string) => {
    const token = mailbox.assertSent({ to: email, mail: VerifyEmailMail }).link('/verify-email').searchParams.get('token');
    await http().post('/verify-email').send({ token }).expect(200);
  };

  it('verifies the address from the mail sent at sign-up, which lets the user order', async () => {
    const { email, cookie } = await signUp();
    const mail = mailbox.assertSent({ to: email, mail: VerifyEmailMail });
    expect(mail).toMatchObject({ subject: 'Confirm your email address', from: { address: 'accounts@example.com' } });

    const refused = await http().get('/orders').set('Cookie', cookie).expect(403);
    expect(refused.body).toEqual({ message: 'Email address not verified', error: 'email_unverified', errorCode: 'email_unverified', statusCode: 403 });

    await verifyEmail(email);
    await http().get('/orders').set('Cookie', cookie).expect(200, { orders: [], email });
    expect(events).toContainEqual({ type: 'email-verified', userId: expect.any(String), email });
  });

  it('resets the password from the mail it sends after answering, and sends nothing for an unknown address', async () => {
    const { email } = await signUp();

    await http().post('/password/forgot').send({ email }).expect(202);
    const mail = await vi.waitFor(() => mailbox.assertSent({ to: email, mail: PasswordResetMail }));
    const token = mail.link('/reset-password').searchParams.get('token');
    await http().post('/password/reset').send({ token, password: 'new password' }).expect(200);
    await http().post('/sign-in').send({ email, password: 'new password' }).expect(200);
    await http().post('/sign-in').send({ email, password: 'old password' }).expect(401);

    await http().post('/password/forgot').send({ email: 'nobody@example.com' }).expect(202);
    await vi.waitFor(() => expect(events).toContainEqual({ type: 'password-reset-requested', email: 'nobody@example.com' }));
    mailbox.assertNotSent({ to: 'nobody@example.com' });
  });

  it('signs in from a magic link mail, in the browser that asked for it, for verified addresses only', async () => {
    const { email } = await signUp();
    await verifyEmail(email);

    const requested = await http().post('/magic').send({ email }).expect(202);
    const token = mailbox.assertSent({ to: email, mail: MagicLinkMail }).link('/magic').searchParams.get('token');
    const signedIn = await http().post('/magic/consume').set('Cookie', cookieOf(requested, '__Host-magic_link_tx')!).send({ token }).expect(200);
    await http().get('/orders').set('Cookie', cookieOf(signedIn, '__Host-sid')!).expect(200);

    const unverified = await signUp();
    const other = await http().post('/magic').send({ email: unverified.email }).expect(202);
    const refusedToken = mailbox.assertSent({ to: unverified.email, mail: MagicLinkMail }).link('/magic').searchParams.get('token');
    await http().post('/magic/consume').set('Cookie', cookieOf(other, '__Host-magic_link_tx')!).send({ token: refusedToken }).expect(401);
    expect(events).toContainEqual({ type: 'magic-link-refused', reason: 'refused', email: unverified.email });
  });

  it('delivers a reset link through a transient transport failure: the mail package retries it', async () => {
    const { email } = await signUp();
    mailbox.failNext(new MailSmtpError('DATA', { code: 451, text: 'Try again later' }));

    await http().post('/password/forgot').send({ email }).expect(202);
    await vi.waitFor(() => mailbox.assertSent({ to: email, mail: PasswordResetMail }));
  });

  it('logs a permanent delivery failure, after the caller got the same answer as everyone', async () => {
    const { email } = await signUp();
    const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
    mailbox.failNext(new MailSmtpError('RCPT TO', { code: 550, text: 'User unknown' }));

    await http().post('/password/forgot').send({ email }).expect(202);
    await vi.waitFor(() =>
      expect(logged).toHaveBeenCalledWith('A password reset request failed', expect.stringContaining('550: User unknown')),
    );
    mailbox.assertNotSent({ to: email, mail: PasswordResetMail });
    logged.mockRestore();
  });
});

describe('shutdown with a reset request in flight', () => {
  it('delivers the link before the app has closed', async () => {
    const mailbox = new InMemoryMailTransport();
    const app = await createApp('express', AppModule, { override: (builder) => builder.overrideProvider(MailTransport).useValue(mailbox) });
    await request(app.getHttpServer()).post('/sign-up').send({ email: 'late@example.com', password: 'old password' }).expect(201);

    let release!: () => void;
    lookupGate = new Promise<void>((resolve) => (release = resolve));
    lookupStarted = false;
    await request(app.getHttpServer()).post('/password/forgot').send({ email: 'late@example.com' }).expect(202);
    await vi.waitFor(() => expect(lookupStarted).toBe(true));

    const closed = app.close();
    release();
    await closed;

    mailbox.assertSent({ to: 'late@example.com', mail: PasswordResetMail });
  });
});
