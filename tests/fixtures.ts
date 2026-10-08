import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Injectable,
  Module,
  NotFoundException,
  Param,
  Post,
  Query,
  UnauthorizedException,
  type ExecutionContext,
  type OnModuleInit,
} from '@nestjs/common';
import {
  Authenticate,
  AuthenticationContext,
  AuthenticationError,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  AuthenticationStorage,
  CurrentSession,
  CurrentUser,
  JwtBearerProvider,
  MagicLinkHandler,
  MagicLinkService,
  MfaService,
  PasswordHasher,
  Public,
  SessionCookieProvider,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationStorageSources,
  type JwtClaims,
  type MagicLink,
  type SessionRecord,
} from '../lib/index.js';
import { LOCK_REGISTRY } from '../lib/services/authentication-registry.service.js';
import { LOCK_STORAGE } from '../lib/storage/authentication.storage.js';
import type { AuthenticationHandlers } from '../lib/index.js';

/**
 * A locked registry with these stores (the in-memory defaults for the
 * rest), for services built with `new`, outside a Nest app.
 */
export function storageWith(sources: AuthenticationStorageSources = {}): AuthenticationStorage {
  const storage = new AuthenticationStorage();
  if (Object.keys(sources).length > 0) {
    storage.registerSource(sources);
  }
  storage[LOCK_STORAGE]({ log: false });
  return storage;
}

/**
 * A locked registry with these options and handlers, for services built
 * with `new`, outside a Nest app.
 */
export function registryWith(options: object = {}, handlers: Partial<AuthenticationHandlers> = {}): AuthenticationRegistry {
  const registry = new AuthenticationRegistry(options as Record<string, unknown>);
  for (const [feature, handler] of Object.entries(handlers)) {
    registry.registerHandler(feature as keyof AuthenticationHandlers, handler as never);
  }
  registry[LOCK_REGISTRY]({ log: false });
  return registry;
}

// ---- Types ------------------------------------------------------------------

export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

declare module '../lib/index.js' {
  interface AuthenticationTypes {
    user: User;
    sessionExtra: { user: User };
  }
}

// ---- Config and users ---------------------------------------------------------

/** Stand-in for ConfigService: the kind of dependency providers inject. */
@Injectable()
export class AppConfig {
  readonly issuer = 'https://api.test';
  readonly audience = 'nest-api';
  readonly keys: { privateKey: KeyObject; publicKey: KeyObject } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

/** Would come from a secret manager. */
export const TOTP_KEY = 'totp-encryption-key-at-least-32-characters';

export const PASSWORDS: Record<string, string> = {
  'alice@example.com': 'correct horse battery staple',
  'bob@example.com': 'bob-password-123',
};

@Injectable()
export class UsersRepository implements OnModuleInit {
  private readonly users = new Map<string, User & { passwordHash?: string }>([
    ['u1', { id: 'u1', email: 'alice@example.com', name: 'Alice', roles: ['editor'] }],
    ['u2', { id: 'u2', email: 'bob@example.com', name: 'Bob', roles: ['viewer'] }],
  ]);

  constructor(private readonly hasher: PasswordHasher) {}

  async onModuleInit() {
    for (const user of this.users.values()) {
      user.passwordHash = await this.hasher.hash(PASSWORDS[user.email]);
    }
  }

  findById(id: string | undefined): User | undefined {
    const found = id ? this.users.get(id) : undefined;
    if (!found) {
      return undefined;
    }

    const { passwordHash: _, ...user } = found;
    return user;
  }

  findByEmail(email: string) {
    return [...this.users.values()].find((u) => u.email === email);
  }

  delete(id: string) {
    this.users.delete(id);
  }
}

// ---- Providers: DI classes ----------------------------------------------------------

/**
 * Provided in UsersModule, second in the chain. Verifies the tokens
 * `TokenService` signs: the module's `accessToken` options reach it through
 * property injection.
 */
@Injectable()
export class JwtAuth extends JwtBearerProvider<User> {
  constructor(
    private readonly users: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerProvider(this, { order: 1 });
  }

  validate(claims: JwtClaims) {
    return this.users.findById(claims.sub);
  }
}

/** Provided in UsersModule, first in the chain. */
@Injectable()
export class SessionAuth extends SessionCookieProvider<User> {
  constructor(
    private readonly users: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerProvider(this);
  }

  validate(session: SessionRecord) {
    return this.users.findById(session.userId);
  }
}

@Injectable()
export class ApiKeyRepository {
  private readonly keys = new Map([
    ['key-ci', { id: 'k1', user: { id: 'svc-ci', email: 'ci@example.com', name: 'CI', roles: ['editor'] } }],
  ]);
  find(key: string) {
    return this.keys.get(key);
  }
}

@Injectable()
export class ApiKeyAuth extends AuthenticationProvider<User, { keyId: string }> {
  constructor(
    private readonly keys: ApiKeyRepository,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerProvider(this, { order: 2 });
  }

  async authenticate(context: ExecutionContext) {
    const key = this.header(context, 'x-api-key');
    if (!key) {
      return null;
    }

    const row = this.keys.find(key);
    if (!row) {
      throw new AuthenticationError('unknown API key', { challenge: 'ApiKey header="x-api-key"' });
    }
    return { user: row.user, session: { keyId: row.id } };
  }

  challenge() {
    return 'ApiKey header="x-api-key"';
  }
}

export const outbox: MagicLink[] = [];

@Injectable()
export class TestMagicLinkHandler extends MagicLinkHandler {
  constructor(
    private readonly users: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('magicLink', this);
  }
  send(link: MagicLink) {
    outbox.push(link);
  }
  resolveUser(email: string) {
    return this.users.findByEmail(email) ?? null;
  }
}

@Module({
  providers: [AppConfig, UsersRepository],
  exports: [AppConfig, UsersRepository],
})
export class UsersModule {}

/** Just the session cookie provider. */
@Module({ imports: [UsersModule], providers: [SessionAuth] })
export class SessionAuthModule {}

/** The app's credential providers (with ApiKeysModule's) and its magic-link handler. */
@Module({ imports: [UsersModule, SessionAuthModule], providers: [JwtAuth, TestMagicLinkHandler] })
export class AuthProvidersModule {}

@Module({ providers: [ApiKeyRepository, ApiKeyAuth], exports: [ApiKeyRepository] })
export class ApiKeysModule {}

// ---- Application ------------------------------------------------------------------

@Injectable()
export class WhoAmIService {
  constructor(private readonly auth: AuthenticationContext) {}

  async whoAmI(delayMs: number) {
    await sleep(delayMs);
    return this.auth.user?.id ?? null;
  }

  requireId() {
    return this.auth.requireUser().id;
  }
}

@Controller('auth')
export class AuthController {
  constructor(
    private readonly users: UsersRepository,
    private readonly hasher: PasswordHasher,
    private readonly signInService: SignInService,
    private readonly sessions: SessionService,
    private readonly mfa: MfaService,
    private readonly tokens: TokenService,
    private readonly magicLinks: MagicLinkService,
  ) {}

  private async checkPassword(email: string, password: string) {
    const user = this.users.findByEmail(email);
    // verify(undefined) still spends the scrypt time: no account enumeration by timing.
    if (!(await this.hasher.verify(password, user?.passwordHash)) || !user) {
      throw new UnauthorizedException();
    }
    return user;
  }

  @Public()
  @Post('login')
  @HttpCode(200)
  async login(@Body() body: { email: string; password: string }) {
    const user = await this.checkPassword(body.email, body.password);
    const { session } = await this.signInService.signIn(user.id, { method: 'password' });
    return { mfa: session.mfa ?? null };
  }

  // Pending sessions are not signed in: completing MFA is public, and reads the cookie.
  @Public()
  @Post('mfa')
  @HttpCode(200)
  async completeMfa(@Body() body: { code?: string; recoveryCode?: string }) {
    const issued = await this.signInService.completeMfa(body);
    if (!issued) {
      throw new UnauthorizedException();
    }
    return { mfa: issued.session.mfa };
  }

  // An enrolled user gets a 409: MfaAlreadyEnrolledError says so on any transport.
  @Post('mfa/enroll')
  enroll(@CurrentUser() user: User) {
    return this.mfa.enroll(user.id, user.email);
  }

  @Authenticate({ mfa: true })
  @Post('mfa/replace')
  replaceAuthenticator(@CurrentUser() user: User) {
    return this.mfa.enroll(user.id, user.email, { replace: true });
  }

  // The code proves this browser has the authenticator: the session becomes MFA-verified.
  @Post('mfa/confirm')
  @HttpCode(200)
  async confirm(@CurrentUser('id') userId: string, @Body('code') code: string) {
    if (!(await this.signInService.confirmMfa(userId, code))) {
      throw new UnauthorizedException();
    }
    return { recoveryCodes: await this.mfa.generateRecoveryCodes(userId) };
  }

  @Public()
  @Post('logout')
  @HttpCode(204)
  async logout() {
    if (!(await this.signInService.signOut())) {
      throw new UnauthorizedException();
    }
  }

  @Post('logout-everywhere')
  @HttpCode(204)
  async logoutEverywhere(@CurrentUser('id') userId: string) {
    await this.signInService.signOutEverywhere(userId);
  }

  @Get('sessions')
  async list(@CurrentUser('id') userId: string, @CurrentSession() current: SessionRecord) {
    return (await this.sessions.list(userId)).map((s) => ({ id: s.id, current: s.id === current.id, metadata: s.metadata }));
  }

  @Delete('sessions/:id')
  @HttpCode(204)
  async revoke(@CurrentUser('id') userId: string, @Param('id') id: string) {
    if (!(await this.sessions.revoke(id, { userId }))) {
      throw new NotFoundException();
    }
  }

  @Post('sessions/revoke-others')
  @HttpCode(204)
  async revokeOthers(@CurrentUser('id') userId: string, @CurrentSession() current: SessionRecord) {
    await this.sessions.revokeAll(userId, { except: current.id });
  }

  @Authenticate({ providers: [SessionCookieProvider] })
  @Post('sessions/rotate')
  @HttpCode(204)
  async rotate() {
    await this.signInService.rotateSession();
  }

  // A user with an authenticator gets tokens only with a code: TokenService asks for it.
  // `amr` in the body stands for an app that puts its own values into the claims.
  @Public()
  @Post('token')
  @HttpCode(200)
  async token(@Body() body: { email: string; password: string; code?: string; recoveryCode?: string; amr?: string[] }) {
    const user = await this.checkPassword(body.email, body.password);
    return this.tokens.issue(user.id, {
      claims: { amr: body.amr ?? ['pwd'] },
      method: 'password',
      secondFactor: { code: body.code, recoveryCode: body.recoveryCode },
    });
  }

  // A RefreshTokenError escaping the handler is a 401.
  @Public()
  @Post('refresh')
  @HttpCode(200)
  refresh(@Body('refreshToken') refreshToken: string) {
    return this.tokens.refresh(refreshToken);
  }

  @Public()
  @Post('magic')
  @HttpCode(202)
  async requestMagicLink(@Body() body: { email: string; redirectTo?: string }) {
    await this.magicLinks.create(body.email, { redirectTo: body.redirectTo });
  }

  @Public()
  @Post('magic/consume')
  @HttpCode(200)
  async consumeMagicLink(@Body('token') token: string) {
    const result = await this.magicLinks.consume(token);
    if (!result) {
      throw new UnauthorizedException();
    }
    return { redirectTo: result.redirectTo ?? '/' };
  }
}

@Controller('me')
export class MeController {
  constructor(private readonly whoAmI: WhoAmIService) {}

  @Get()
  me(@CurrentUser() user: User, @CurrentUser('email') email: string, @CurrentSession() session: unknown) {
    return { user, email, session };
  }

  @Get('context')
  async context(@Query('delay') delay = '0') {
    return { id: await this.whoAmI.whoAmI(Number(delay)) };
  }

  @Get('sensitive')
  @Authenticate({ mfa: true })
  sensitive() {
    return { ok: true };
  }
}

@Controller('feed')
export class FeedController {
  constructor(private readonly whoAmI: WhoAmIService) {}

  @Get()
  @Authenticate({ optional: true })
  feed(@CurrentUser() user: User | null) {
    return { personalizedFor: user?.id ?? null };
  }

  // requireUser() in a service: a 401 for anonymous callers, whatever the route allows.
  @Get('mine')
  @Authenticate({ optional: true })
  mine() {
    return { id: this.whoAmI.requireId() };
  }
}

@Controller('public')
@Public()
export class PublicController {
  constructor(private readonly auth: AuthenticationContext) {}

  @Get()
  open(@CurrentUser() user: User | null) {
    return { open: true, user, contextUser: this.auth.user };
  }

  @Get('strict')
  @Authenticate()
  strict(@CurrentUser('id') id: string) {
    return { id };
  }
}

export const authenticationModule = () =>
  AuthenticationModule.forRootAsync({
    imports: [UsersModule],
    inject: [AppConfig],
    useFactory: (config: AppConfig) => ({
      session: {
        cookie: { secure: false }, // supertest talks plain HTTP
        metadata: ({ headers }) => ({ userAgent: headers['user-agent'] ?? null }),
      },
      password: { logN: 10 }, // fast for tests; the default is 17
      mfa: { issuer: 'Nest POC', encryption: { keys: [TOTP_KEY] } },
      magicLink: { url: `${config.issuer}/magic` },
      accessToken: {
        key: config.keys.privateKey, // ES256, from the key
        kid: 'k1',
        issuer: config.issuer,
        audience: config.audience,
        ttl: '5m',
      },
    }),
  });

@Module({
  imports: [authenticationModule(), UsersModule, AuthProvidersModule, ApiKeysModule],
  controllers: [AuthController, MeController, FeedController, PublicController],
  providers: [WhoAmIService],
})
export class AppModule {}
