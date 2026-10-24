/**
 * The storage recipes the docs ship (the tutorial's Drizzle and TypeORM stores, copied into
 * tests/fixtures), registered the way an app registers them, under a real app on Express and
 * Fastify: every feature's flow over HTTP, with assertions on the rows each one leaves behind.
 * Drizzle runs on PGlite and PostgreSQL, TypeORM on PostgreSQL and on PGlite through its
 * socket server (TypeORM needs a wire-protocol connection). PostgreSQL is the server in
 * SQL_TEST_PG_URL or a throwaway local cluster, and its targets skip, with the reason,
 * without either.
 */
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { PGLiteSocketServer } from '@electric-sql/pglite-socket';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Injectable,
  Module,
  Param,
  Post,
  Query,
  Redirect,
  UnauthorizedException,
  type INestApplication,
  type Provider,
  type Type,
} from '@nestjs/common';
import { getDrizzleToken } from '@nestjs/drizzle';
import { drizzle as drizzleNodePostgres } from 'drizzle-orm/node-postgres';
import { migrate as migrateNodePostgres } from 'drizzle-orm/node-postgres/migrator';
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite';
import { migrate as migratePglite } from 'drizzle-orm/pglite/migrator';
import { Pool } from 'pg';
import request from 'supertest';
import { DataSource } from 'typeorm';
import { adapters, createApp } from './support/adapters.js';
import { startPostgres } from './support/postgres.js';
import {
  Authenticate,
  AuthenticationModule,
  AuthenticationRegistry,
  AuthenticationStorage,
  CurrentUser,
  JwtBearerProvider,
  MagicLinkHandler,
  MagicLinkService,
  MfaService,
  OidcAccountResolver,
  OidcService,
  PasswordHasher,
  PasswordResetHandler,
  PasswordResetService,
  Public,
  SessionCookieProvider,
  SessionService,
  SignInService,
  TokenService,
  type JwtClaims,
  type MagicLink,
  type OidcProfile,
  type PasswordResetLink,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';
import { DrizzleAuthenticationStore } from './fixtures/database/drizzle-authentication.store.js';
import { dataSourceOptions } from './fixtures/typeorm/data-source.js';
import { TypeOrmAuthenticationStore } from './fixtures/typeorm/typeorm-authentication.store.js';
import { MockOidcProvider } from './mock-oidc.js';

const migrationsFolder = fileURLToPath(new URL('./fixtures/drizzle', import.meta.url));

const TOTP_KEY = 'database-test-totp-key-of-at-least-32-chars';
const sha256 = (value: string) => createHash('sha256').update(value).digest('base64url');
// The app's TOTP clock (`mfa.now`), fixed when the file loads: on the wall clock the 30-second step
// can turn between making a code and the app checking it, and the previous step's code is then refused.
const clock = Date.now();
const totp = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(clock / 30_000) + offset);

interface Database {
  providers: Provider[];
  store: Type;
  query(text: string, params?: unknown[]): Promise<Record<string, any>[]>;
  close(): Promise<void>;
}

interface Target {
  name: string;
  postgres?: boolean;
  open(): Promise<Database>;
}

const { postgres, reason: postgresMissing } = await startPostgres();
afterAll(() => postgres?.stop());

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
  });
}

async function drizzleOn(client: Pool | PGlite): Promise<Database> {
  if (client instanceof PGlite) {
    const db = drizzlePglite(client);
    await migratePglite(db, { migrationsFolder });
    return {
      providers: [{ provide: getDrizzleToken(), useValue: db }, DrizzleAuthenticationStore],
      store: DrizzleAuthenticationStore,
      query: async (text, params) => (await client.query<Record<string, any>>(text, params)).rows,
      close: () => client.close(),
    };
  }

  const db = drizzleNodePostgres(client);
  await migrateNodePostgres(db, { migrationsFolder });
  return {
    providers: [{ provide: getDrizzleToken(), useValue: db }, DrizzleAuthenticationStore],
    store: DrizzleAuthenticationStore,
    query: async (text, params) => (await client.query(text, params)).rows,
    close: () => client.end(),
  };
}

async function typeOrmOn(url: string, onClose: () => Promise<void> = async () => {}): Promise<Database> {
  const dataSource = await new DataSource({ ...dataSourceOptions, url } as ConstructorParameters<typeof DataSource>[0]).initialize();
  await dataSource.runMigrations();

  return {
    providers: [{ provide: DataSource, useValue: dataSource }, TypeOrmAuthenticationStore],
    store: TypeOrmAuthenticationStore,
    query: (text, params) => dataSource.query(text, params),
    close: async () => {
      await dataSource.destroy();
      await onClose();
    },
  };
}

const targets: Target[] = [
  { name: 'Drizzle on PGlite', open: () => drizzleOn(new PGlite()) },
  {
    name: 'Drizzle on PostgreSQL',
    postgres: true,
    open: async () => drizzleOn(new Pool({ connectionString: await postgres!.createDatabase('authentication_drizzle_app'), max: 5 })),
  },
  {
    name: 'TypeORM on PGlite (socket server)',
    open: async () => {
      const db = new PGlite();
      const port = await freePort();
      const server = new PGLiteSocketServer({ db, port, host: '127.0.0.1' });
      await server.start();
      return typeOrmOn(`postgres://postgres@127.0.0.1:${port}/postgres`, async () => {
        await server.stop();
        await db.close();
      });
    },
  },
  {
    name: 'TypeORM on PostgreSQL',
    postgres: true,
    open: async () => typeOrmOn(await postgres!.createDatabase('authentication_typeorm_app')),
  },
];

// ---- The app ----------------------------------------------------------------------------

interface Account {
  id: string;
  email: string;
  passwordHash: string | null;
}

const idp = new MockOidcProvider();
const mails: (MagicLink | PasswordResetLink)[] = [];

@Injectable()
class Accounts {
  readonly rows = new Map<string, Account>();
  private next = 0;

  constructor(private readonly hasher: PasswordHasher) {}

  async add(password = 'old password') {
    const id = `db-user-${process.pid}-${++this.next}-${Math.random().toString(36).slice(2, 8)}`;
    const row = { id, email: `${id}@example.com`, passwordHash: await this.hasher.hash(password) };
    this.rows.set(id, row);
    return row;
  }
  byEmail(email: string) {
    return [...this.rows.values()].find((row) => row.email === email);
  }
  user(id: string | undefined) {
    const row = id ? this.rows.get(id) : undefined;
    return row && { id: row.id, email: row.email };
  }
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
    return this.accounts.user(session.userId);
  }
}

@Injectable()
class BearerAuth extends JwtBearerProvider<{ id: string; email: string }> {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerProvider(this, { order: 1 });
  }
  validate(claims: JwtClaims) {
    return this.accounts.user(claims.sub);
  }
}

@Injectable()
class Mailers extends MagicLinkHandler {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('magicLink', this);
  }
  send(link: MagicLink) {
    mails.push(link);
  }
  resolveUser(email: string) {
    return this.accounts.user(this.accounts.byEmail(email)?.id) ?? null;
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
  findUser(email: string) {
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

/** The IdP's subject is the account id. */
@Injectable()
class Identities extends OidcAccountResolver {
  constructor(
    private readonly accounts: Accounts,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('oidc', this);
  }
  resolveUser(profile: OidcProfile) {
    return this.accounts.user(profile.subject) ?? null;
  }
}

@Controller()
class AppController {
  constructor(
    private readonly accounts: Accounts,
    private readonly hasher: PasswordHasher,
    private readonly signInService: SignInService,
    private readonly sessionService: SessionService,
    private readonly mfaService: MfaService,
    private readonly tokenService: TokenService,
    private readonly magicLinkService: MagicLinkService,
    private readonly passwordResetService: PasswordResetService,
    private readonly oidcService: OidcService,
  ) {}

  private async account(email: string, password: string) {
    const row = this.accounts.byEmail(email);
    if (!(await this.hasher.verify(password, row?.passwordHash ?? undefined)) || !row) {
      throw new UnauthorizedException();
    }
    return row;
  }

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn(@Body() body: { email: string; password: string }) {
    const row = await this.account(body.email, body.password);
    const { session } = await this.signInService.signIn(row.id, { method: 'password' });
    return { mfaRequired: session.mfa === 'pending' };
  }

  @Public()
  @Post('sign-out')
  @HttpCode(204)
  async signOut() {
    if (!(await this.signInService.signOut())) {
      throw new UnauthorizedException();
    }
  }

  @Post('sign-out-everywhere')
  @HttpCode(204)
  async signOutEverywhere(@CurrentUser('id') userId: string) {
    await this.signInService.signOutEverywhere(userId);
  }

  @Get('me')
  me(@CurrentUser('id') id: string) {
    return { id };
  }

  @Authenticate({ mfa: true })
  @Get('me/sensitive')
  sensitive() {
    return { ok: true };
  }

  @Get('sessions')
  async sessions(@CurrentUser('id') userId: string) {
    return (await this.sessionService.list(userId)).map((session) => session.metadata);
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

  @Public()
  @Post('mfa/complete')
  @HttpCode(200)
  async complete(@Body() body: { code?: string; recoveryCode?: string }) {
    if (!(await this.signInService.completeMfa(body))) {
      throw new UnauthorizedException();
    }
    return { ok: true };
  }

  @Public()
  @Post('token')
  @HttpCode(200)
  async token(@Body() body: { email: string; password: string }) {
    const row = await this.account(body.email, body.password);
    return this.tokenService.issue(row.id, { method: 'password', claims: { amr: ['pwd'] } });
  }

  @Public()
  @Post('token/refresh')
  @HttpCode(200)
  refresh(@Body('refreshToken') refreshToken: string) {
    return this.tokenService.refresh(refreshToken);
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
    return { ok: true };
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
    return { ok: true };
  }

  @Public()
  @Get('oidc/:provider/login')
  @Redirect()
  oidcLogin(@Param('provider') provider: string) {
    return this.oidcService.start(provider);
  }

  @Public()
  @Get('oidc/:provider/callback')
  @Redirect()
  oidcCallback(@Param('provider') provider: string, @Query() query: Record<string, string>) {
    return this.oidcService.finish(provider, query);
  }
}

function appModule(database: Database) {
  @Module({
    imports: [
      AuthenticationModule.forRootAsync({
        useFactory: () => ({
          session: { metadata: ({ headers }) => ({ userAgent: headers['user-agent'] ?? null }) },
          password: { logN: 10 },
          mfa: { issuer: 'DB test', encryption: { keys: [TOTP_KEY] }, now: () => clock },
          accessToken: { key: 'database-test-jwt-secret-of-at-least-32-bytes' },
          magicLink: { url: 'https://app.test/magic' },
          passwordReset: { url: 'https://app.test/reset-password' },
          oidc: {
            callbackUrl: 'https://app.test/oidc/:provider/callback',
            providers: { mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret } },
          },
        }),
      }),
    ],
    controllers: [AppController],
    providers: [...database.providers, Accounts, SessionAuth, BearerAuth, Mailers, ResetMailer, Identities],
  })
  class DatabaseAppModule {}
  return DatabaseAppModule;
}

const cookieOf = (res: request.Response, name: string) =>
  ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith(`${name}=`))?.split(';')[0];
const valueOf = (cookie: string) => cookie.slice(cookie.indexOf('=') + 1);
const tokenOf = (link: { url: string }) => new URL(link.url).searchParams.get('token')!;

beforeAll(() => idp.start());
afterAll(() => idp.stop());

const title = (target: Target) =>
  target.postgres && !postgres ? `${target.name} (skipped: ${postgresMissing!.split('\n')[0]})` : target.name;

for (const target of targets) {
  describe.skipIf(target.postgres && !postgres)(title(target), () => {
    let database: Database;

    beforeAll(async () => {
      database = await target.open();
    }, 60_000);
    afterAll(() => database?.close());

    describe.each(adapters.map((a) => a.name))('on %s', (adapter) => {
      let app: INestApplication;
      let accounts: Accounts;
      const http = () => request(app.getHttpServer());
      const rows = (text: string, ...params: unknown[]) => database.query(text, params);

      beforeAll(async () => {
        // The production guard accepts the recipe for every contract the configuration uses.
        const nodeEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';
        try {
          app = await createApp(adapter, appModule(database));
        } finally {
          process.env.NODE_ENV = nodeEnv;
        }
        accounts = app.get(Accounts);
      }, 30_000);
      afterAll(() => app?.close());
      beforeEach(() => {
        mails.length = 0;
      });

      async function signIn(email: string, password = 'old password', headers: Record<string, string> = {}) {
        const res = await http().post('/sign-in').set(headers).send({ email, password }).expect(200);
        return { cookie: cookieOf(res, '__Host-sid')!, mfaRequired: res.body.mfaRequired as boolean };
      }

      it('serves every contract from the registered store', () => {
        const storage = app.get(AuthenticationStorage);
        const store = app.get(database.store);

        expect([storage.sessions, storage.refreshTokens, storage.mfa, storage.magicLinks, storage.oidcStates, storage.emailTokens]).toEqual(
          Array(6).fill(store),
        );
      });

      it('keeps sessions as rows under the hash of the cookie, with their metadata, and deletes them on sign-out', async () => {
        const user = await accounts.add();
        const first = await signIn(user.email, undefined, { 'User-Agent': 'db-browser' });

        expect(await rows('SELECT id, mfa, metadata FROM sessions WHERE user_id = $1', user.id)).toEqual([
          { id: sha256(valueOf(first.cookie)), mfa: null, metadata: { userAgent: 'db-browser' } },
        ]);
        await http().get('/me').set('Cookie', first.cookie).expect(200, { id: user.id });

        // A second sign-in from the same browser replaces its row (fixation defence).
        const res = await http().post('/sign-in').set('Cookie', first.cookie).send({ email: user.email, password: 'old password' }).expect(200);
        const second = cookieOf(res, '__Host-sid')!;
        expect(await rows('SELECT id FROM sessions WHERE user_id = $1', user.id)).toEqual([{ id: sha256(valueOf(second)) }]);
        await http().get('/me').set('Cookie', first.cookie).expect(401);

        await http().post('/sign-out').set('Cookie', second).expect(204);
        expect(await rows('SELECT id FROM sessions WHERE user_id = $1', user.id)).toEqual([]);
        await http().get('/me').set('Cookie', second).expect(401);
      });

      it('lists the user’s sessions from the table, and signing out everywhere deletes every row and revokes every family', async () => {
        const user = await accounts.add();
        const laptop = await signIn(user.email, undefined, { 'User-Agent': 'laptop' });
        await signIn(user.email, undefined, { 'User-Agent': 'phone' });
        await http().post('/token').send({ email: user.email, password: 'old password' }).expect(200);

        const listed = await http().get('/sessions').set('Cookie', laptop.cookie).expect(200);
        expect(listed.body).toEqual(expect.arrayContaining([{ userAgent: 'laptop' }, { userAgent: 'phone' }]));

        await http().post('/sign-out-everywhere').set('Cookie', laptop.cookie).expect(204);
        expect(await rows('SELECT id FROM sessions WHERE user_id = $1', user.id)).toEqual([]);
        expect(await rows('SELECT revoked FROM refresh_tokens WHERE user_id = $1', user.id)).toEqual([{ revoked: true }]);
      });

      it('rotates refresh tokens within a family and revokes the whole family on reuse', async () => {
        const user = await accounts.add();
        const issued = (await http().post('/token').send({ email: user.email, password: 'old password' }).expect(200)).body;
        await http().get('/me').set('Authorization', `Bearer ${issued.accessToken}`).expect(200, { id: user.id });

        const [family] = await rows('SELECT id, family_id, used_at, claims FROM refresh_tokens WHERE user_id = $1', user.id);
        expect(family).toEqual({ id: sha256(issued.refreshToken), family_id: expect.any(String), used_at: null, claims: { amr: ['pwd'] } });

        const rotated = (await http().post('/token/refresh').send({ refreshToken: issued.refreshToken }).expect(200)).body;
        const afterRotation = await rows('SELECT id, used_at, revoked FROM refresh_tokens WHERE family_id = $1 ORDER BY created_at', family.family_id);
        expect(afterRotation).toEqual([
          { id: sha256(issued.refreshToken), used_at: expect.any(Date), revoked: false },
          { id: sha256(rotated.refreshToken), used_at: null, revoked: false },
        ]);

        const reused = await http().post('/token/refresh').send({ refreshToken: issued.refreshToken }).expect(401);
        expect(reused.body).toMatchObject({ statusCode: 401 });
        expect(await rows('SELECT DISTINCT revoked FROM refresh_tokens WHERE family_id = $1', family.family_id)).toEqual([{ revoked: true }]);
        await http().post('/token/refresh').send({ refreshToken: rotated.refreshToken }).expect(401);
      });

      it('stores the TOTP secret encrypted and recovery codes hashed, and runs the second factor on the table', async () => {
        const user = await accounts.add();
        const { cookie } = await signIn(user.email);
        const { secret } = (await http().post('/mfa/enroll').set('Cookie', cookie).expect(201)).body;

        const [enrolled] = await rows('SELECT secret, confirmed FROM mfa_authenticators WHERE user_id = $1', user.id);
        expect(enrolled.confirmed).toBe(false);
        expect(enrolled.secret).toMatch(/^v1\.[\w-]{8}\./);
        expect(enrolled.secret).not.toContain(secret);

        const confirmed = await http().post('/mfa/confirm').set('Cookie', cookie).send({ code: totp(secret, -1) }).expect(200);
        const recoveryCodes: string[] = confirmed.body.recoveryCodes;
        expect(await rows('SELECT confirmed FROM mfa_authenticators WHERE user_id = $1', user.id)).toEqual([{ confirmed: true }]);
        const stored = await rows('SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1', user.id);
        expect(stored).toHaveLength(10);
        expect(stored.map((row) => row.code_hash)).not.toEqual(expect.arrayContaining([recoveryCodes[0]]));
        expect(await rows('SELECT mfa FROM sessions WHERE user_id = $1', user.id)).toEqual([{ mfa: 'verified' }]);

        // The next sign-in is pending until the second factor, and a wrong code is a row in mfa_failures.
        const pending = await signIn(user.email);
        expect(pending.mfaRequired).toBe(true);
        expect(await rows('SELECT mfa FROM sessions WHERE id = $1', sha256(valueOf(pending.cookie)))).toEqual([{ mfa: 'pending' }]);
        await http().get('/me').set('Cookie', pending.cookie).expect(401);
        await http().post('/mfa/complete').set('Cookie', pending.cookie).send({ code: '000000' }).expect(401);
        expect(await rows('SELECT user_id FROM mfa_failures WHERE user_id = $1', user.id)).toHaveLength(1);

        const step = Math.floor(clock / 30_000);
        const code = hotp(base32Decode(secret), step);
        const completed = await http().post('/mfa/complete').set('Cookie', pending.cookie).send({ code }).expect(200);
        const verified = cookieOf(completed, '__Host-sid')!;
        await http().get('/me/sensitive').set('Cookie', verified).expect(200, { ok: true });
        expect(await rows('SELECT last_used_step FROM mfa_authenticators WHERE user_id = $1', user.id)).toEqual([{ last_used_step: step }]);

        // A recovery code works once: its row is gone after.
        const again = await signIn(user.email);
        await http().post('/mfa/complete').set('Cookie', again.cookie).send({ recoveryCode: recoveryCodes[0] }).expect(200);
        expect(await rows('SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1', user.id)).toHaveLength(9);
        const third = await signIn(user.email);
        await http().post('/mfa/complete').set('Cookie', third.cookie).send({ recoveryCode: recoveryCodes[0] }).expect(401);
      });

      it('keeps a magic link as a row until it is used once', async () => {
        const user = await accounts.add();
        const requested = await http().post('/magic').send({ email: user.email }).expect(202);
        const tx = cookieOf(requested, '__Host-magic_link_tx')!;
        const token = tokenOf(mails.at(-1)!);

        // Stored under the token and the browser's secret together: the link alone finds no row.
        const id = sha256(`${token}.${valueOf(tx).split('.')[1]}`);
        expect(await rows('SELECT id, email FROM magic_links WHERE id = $1', id)).toEqual([{ id, email: user.email }]);
        expect(await rows('SELECT id FROM magic_links WHERE id = $1', sha256(token))).toEqual([]);

        const consumed = await http().post('/magic/consume').set('Cookie', tx).send({ token }).expect(200);
        await http().get('/me').set('Cookie', cookieOf(consumed, '__Host-sid')!).expect(200, { id: user.id });
        expect(await rows('SELECT id FROM magic_links WHERE id = $1', id)).toEqual([]);
        await http().post('/magic/consume').set('Cookie', tx).send({ token }).expect(401);
      });

      it('keeps a password reset link as a row, and a reset ends every session and family of the user', async () => {
        const user = await accounts.add();
        const { cookie } = await signIn(user.email);
        await http().post('/token').send({ email: user.email, password: 'old password' }).expect(200);

        await http().post('/password/forgot').send({ email: user.email }).expect(202);
        await vi.waitFor(() => expect(mails).toHaveLength(1));
        const token = tokenOf(mails[0]);
        expect(await rows('SELECT purpose, email FROM email_tokens WHERE id = $1', sha256(token))).toEqual([
          { purpose: 'password-reset', email: user.email },
        ]);

        await http().post('/password/reset').send({ token, password: 'new password' }).expect(200);
        expect(await rows('SELECT id FROM email_tokens WHERE user_id = $1', user.id)).toEqual([]);
        expect(await rows('SELECT id FROM sessions WHERE user_id = $1', user.id)).toEqual([]);
        expect(await rows('SELECT DISTINCT revoked FROM refresh_tokens WHERE user_id = $1', user.id)).toEqual([{ revoked: true }]);
        await http().get('/me').set('Cookie', cookie).expect(401);

        await http().post('/password/reset').send({ token, password: 'another password' }).expect(400);
        await signIn(user.email, 'new password');
      });

      it('keeps an OpenID Connect login as a row between the redirect and the callback', async () => {
        const user = await accounts.add();
        const started = await http().get('/oidc/mock/login').expect(302);
        const location = started.headers.location as string;
        const state = new URL(location).searchParams.get('state')!;

        expect(await rows('SELECT provider, code_verifier IS NOT NULL AS has_verifier FROM oidc_logins WHERE state = $1', state)).toEqual([
          { provider: 'mock', has_verifier: true },
        ]);

        const code = idp.approve(location, { sub: user.id });
        const finished = await http()
          .get('/oidc/mock/callback')
          .query({ code, state })
          .set('Cookie', cookieOf(started, '__Host-oidc_tx')!)
          .expect(302);
        await http().get('/me').set('Cookie', cookieOf(finished, '__Host-sid')!).expect(200, { id: user.id });
        expect(await rows('SELECT state FROM oidc_logins WHERE state = $1', state)).toEqual([]);
      });
    });
  });
}
