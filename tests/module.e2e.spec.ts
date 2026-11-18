import {
  Controller,
  Get,
  Injectable,
  Logger,
  Module,
  ServiceUnavailableException,
  UseGuards,
  UseInterceptors,
  type CallHandler,
  type ExecutionContext,
  type INestApplication,
  type ModuleMetadata,
  type NestInterceptor,
  type Provider,
  type Type,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { defer, retry } from 'rxjs';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AUTHENTICATION_MODULE_OPTIONS,
  AuthenticationContext,
  AuthenticationGuard,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentUser,
  JwtBearerProvider,
  MagicLinkHandler,
  PasswordHasher,
  SessionCookieProvider,
  SessionService,
  TokenService,
  google,
  type AuthenticationModuleAsyncOptions,
  type AuthenticationModuleOptions,
  type AuthenticationOptionsFactory,
  type JwtClaims,
  type SessionRecord,
} from '../lib/index.js';

/** Authenticates `x-user: <id>`: enough to see which routes the guard covers. */
@Injectable()
class HeaderAuth extends AuthenticationProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  authenticate(context: ExecutionContext) {
    const id = this.header(context, 'X-User');
    return id ? { user: { id } } : null;
  }
}

@Controller('me')
class MeController {
  @Get()
  me(@CurrentUser('id') id: string) {
    return { id };
  }
}

@Controller('guarded')
@UseGuards(AuthenticationGuard)
class GuardedController {
  @Get()
  me(@CurrentUser('id') id: string) {
    return { id };
  }
}

const boot = async (
  authentication: ReturnType<typeof AuthenticationModule.forRoot>,
  { controllers = [MeController], providers = [HeaderAuth] }: { controllers?: Type<unknown>[]; providers?: Provider[] } = {},
) => {
  @Module({ imports: [authentication], controllers, providers })
  class AppModule {}
  return createApp('express', AppModule);
};

describe('AuthenticationModule registration', () => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('forRoot() takes plain values, which the options token holds', async () => {
    app = await boot(AuthenticationModule.forRoot({ session: { cookieName: 'session', idleTtl: '1h' } }));
    expect(app.get(AUTHENTICATION_MODULE_OPTIONS)).toEqual({ session: { cookieName: 'session', idleTtl: '1h' } });
    await request(app.getHttpServer()).get('/me').set('X-User', 'u1').expect(200, { id: 'u1' });
    await request(app.getHttpServer()).get('/me').expect(401);
  });

  it('forRootAsync() takes useClass and useExisting factories: createAuthenticationOptions()', async () => {
    @Injectable()
    class AuthConfig implements AuthenticationOptionsFactory {
      createAuthenticationOptions(): AuthenticationModuleOptions {
        return { password: { logN: 10 } };
      }
    }
    @Module({ providers: [AuthConfig], exports: [AuthConfig] })
    class ConfigModule {}

    app = await boot(AuthenticationModule.forRootAsync({ useClass: AuthConfig }));
    expect(await app.get(PasswordHasher).hash('pw')).toMatch(/^\$scrypt\$ln=10,/);
    await app.close();

    // What a library that wraps the module passes through.
    const wrapped: AuthenticationModuleAsyncOptions = { imports: [ConfigModule], useExisting: AuthConfig };
    app = await boot(AuthenticationModule.forRootAsync(wrapped));
    expect(await app.get(PasswordHasher).hash('pw')).toMatch(/^\$scrypt\$ln=10,/);
  });

  it('isGlobal defaults to true, and can be turned off', () => {
    expect(AuthenticationModule.forRoot().global).toBe(true);
    expect(AuthenticationModule.forRoot({ isGlobal: false }).global).toBe(false);
    expect(AuthenticationModule.forRootAsync({ isGlobal: false, useFactory: () => ({}) }).global).toBe(false);
  });

  it('globalGuard: false leaves routes open unless they use AuthenticationGuard', async () => {
    app = await boot(AuthenticationModule.forRoot({ globalGuard: false }), { controllers: [MeController, GuardedController] });
    await request(app.getHttpServer()).get('/me').expect(200, { id: null });
    await request(app.getHttpServer()).get('/guarded').expect(401);
    await request(app.getHttpServer()).get('/guarded').set('X-User', 'u2').expect(200, { id: 'u2' });
  });

  it('takes providers built with `new` too, the base classes included, registered from a factory provider', async () => {
    class Sessions extends SessionCookieProvider<{ id: string }> {
      validate(session: SessionRecord) {
        return { id: session.userId };
      }
    }
    class Tokens extends JwtBearerProvider<{ id: string }> {
      validate(claims: JwtClaims) {
        return { id: claims.sub! };
      }
    }

    const register: Provider = {
      provide: 'REGISTER_PROVIDERS',
      inject: [AuthenticationRegistry],
      useFactory: (registry: AuthenticationRegistry) => {
        registry.registerProvider(new Sessions());
        registry.registerProvider(new Tokens(), { order: 1 });
      },
    };

    app = await boot(AuthenticationModule.forRoot({ accessToken: { key: 's'.repeat(32) } }), { providers: [register] });
    const { cookie } = await app.get(SessionService).create('u1');
    await request(app.getHttpServer()).get('/me').set('Cookie', cookie.split(';')[0]).expect(200, { id: 'u1' });

    const { accessToken } = await app.get(TokenService).issue('u2');
    await request(app.getHttpServer()).get('/me').set('Authorization', `Bearer ${accessToken}`).expect(200, { id: 'u2' });
  });
});

/** Answers every request as `id`: which one wins shows the order. */
function answering(id: string, order?: number) {
  @Injectable()
  class Answers extends AuthenticationProvider<{ id: string }> {
    constructor(registry: AuthenticationRegistry) {
      super();
      registry.registerProvider(this, order === undefined ? undefined : { order });
    }
    authenticate() {
      return { user: { id } };
    }
  }
  Object.defineProperty(Answers, 'name', { value: `${id[0].toUpperCase()}${id.slice(1)}Auth` });
  return Answers;
}

describe('AuthenticationRegistry', () => {
  const start = async (imports: ModuleMetadata['imports'], providers: Provider[] = []) => {
    const moduleRef = await Test.createTestingModule({ imports, providers }).compile();
    await moduleRef.init();
    return moduleRef;
  };
  let log: ReturnType<typeof vi.spyOn>;
  let warn: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => {
    log.mockRestore();
    warn.mockRestore();
  });

  describe('credential providers', () => {
    it('run in ascending `order`, whatever order Nest constructed them in', async () => {
      // Constructed first, listed first, but order 2.
      const Late = answering('late', 2);
      const Early = answering('early', 1);

      const app = await boot(AuthenticationModule.forRoot(), { providers: [Late, Early] });
      await request(app.getHttpServer()).get('/me').expect(200, { id: 'early' });
      expect(app.get(AuthenticationRegistry).providers.map((provider) => provider.constructor.name)).toEqual(['EarlyAuth', 'LateAuth']);
      await app.close();
    });

    it('refuse to share an order, naming both, and suggest the next free one', async () => {
      await expect(start([AuthenticationModule.forRoot()], [HeaderAuth, answering('other')])).rejects.toThrow(
        "AuthenticationRegistry.registerProvider(): OtherAuth can't take order 0, HeaderAuth has it. Providers run in ascending " +
          '`order` and the first that returns a user wins, so each needs its own: `registerProvider(this, { order: 1 })`.',
      );
    });

    it('refuse the same class twice: it was provided in two modules', async () => {
      @Module({ providers: [HeaderAuth] })
      class First {}
      @Module({ providers: [HeaderAuth] })
      class Second {}

      await expect(start([AuthenticationModule.forRoot(), First, Second])).rejects.toThrow(
        'AuthenticationRegistry.registerProvider(): another HeaderAuth is already registered at order 0. Is the class provided in two modules?',
      );
    });

    it('replace the provider at the same order with { replace: true } (tests, wrappers)', async () => {
      const fake: Provider = {
        provide: 'FAKE',
        inject: [AuthenticationRegistry, HeaderAuth],
        useFactory: (registry: AuthenticationRegistry) =>
          registry.registerProvider({ authenticate: () => ({ user: { id: 'fake' } }) }, { replace: true }),
      };

      const app = await boot(AuthenticationModule.forRoot(), { providers: [HeaderAuth, fake] });
      await request(app.getHttpServer()).get('/me').set('X-User', 'u1').expect(200, { id: 'fake' });
      await app.close();
    });

    it('are checked at once: an instance with authenticate(), and a finite order', () => {
      const registry = new AuthenticationRegistry();

      expect(() => registry.registerProvider(HeaderAuth as never)).toThrow(
        'AuthenticationRegistry.registerProvider(): expected a credential provider with an authenticate() method, got the class HeaderAuth (pass an instance: `this`).',
      );
      expect(() => registry.registerProvider({} as never)).toThrow('with an authenticate() method, got an object.');
      expect(() => registry.registerProvider({ authenticate: () => null }, { order: Number.NaN })).toThrow(
        '`order` must be a finite number, got NaN.',
      );

      const provider = { authenticate: () => null };
      registry.registerProvider(provider);
      expect(() => registry.registerProvider(provider, { order: 1 })).toThrow('an object is already registered (the same instance, twice).');
    });
  });

  describe('feature handlers', () => {
    const magicLink = { send() {}, resolveUser: () => null };

    it('are checked at once: a known feature, and every method of its handler', () => {
      const registry = new AuthenticationRegistry();

      expect(() => registry.registerHandler('magic' as never, magicLink as never)).toThrow(
        'AuthenticationRegistry.registerHandler(): unknown feature `magic`. The features are emailVerification (EmailVerificationHandler), ' +
          'passwordReset (PasswordResetHandler), magicLink (MagicLinkHandler), oidc (OidcAccountResolver).',
      );

      expect(() => registry.registerHandler('passwordReset', { send() {} } as never)).toThrow(
        "AuthenticationRegistry.registerHandler(): an object doesn't implement PasswordResetHandler for `passwordReset`: findUser(), updatePassword() are missing.",
      );
      expect(() =>
        registry.registerHandler('passwordReset', { findUser: () => null, send() {}, updatePassword() {}, hashPassword: 'argon2' } as never),
      ).toThrow(
        "AuthenticationRegistry.registerHandler(): an object doesn't implement PasswordResetHandler for `passwordReset`: `hashPassword` is set, but not a method.",
      );
      expect(() => registry.registerHandler('oidc', null as never)).toThrow('expected a OidcAccountResolver as `oidc`, got null.');
    });

    it('register once per feature, unless { replace: true }', () => {
      class Links extends MagicLinkHandler {
        send() {}
        resolveUser() {
          return null;
        }
      }

      const registry = new AuthenticationRegistry({ magicLink: { url: 'https://example.com/magic' } });
      const first = new Links();
      registry.registerHandler('magicLink', first);

      expect(() => registry.registerHandler('magicLink', magicLink)).toThrow(
        "AuthenticationRegistry.registerHandler(): an object can't register `magicLink`, Links already did. Register each feature once, " +
          'or pass { replace: true } to replace it on purpose (tests, wrappers).',
      );

      registry.registerHandler('magicLink', magicLink, { replace: true });
      expect(registry.handler('magicLink')).toBe(magicLink);
    });
  });

  describe('the lock', () => {
    it('comes at startup: registering later throws', async () => {
      const moduleRef = await start([AuthenticationModule.forRoot()], [HeaderAuth]);
      expect(() => moduleRef.get(AuthenticationRegistry).registerProvider({ authenticate: () => null }, { order: 1 })).toThrow(
        'AuthenticationRegistry.registerProvider(): an object registered after AuthenticationModule initialized (or after the registry ' +
          'was first read). Register from the constructor of a singleton provider',
      );
      await moduleRef.close();
    });

    it("comes at the first read too, if that is before AuthenticationModule's onModuleInit", () => {
      const registry = new AuthenticationRegistry();
      registry.registerProvider({ authenticate: () => null });
      expect(registry.providers).toHaveLength(1);
      expect(() => registry.registerHandler('oidc', { resolveUser: () => null })).toThrow(/registered after AuthenticationModule initialized/);
    });

    it('logs the chain and the handlers', async () => {
      const handlers: Provider = {
        provide: 'HANDLERS',
        inject: [AuthenticationRegistry],
        useFactory: (registry: AuthenticationRegistry) => {
          class MagicLinkMailer extends MagicLinkHandler {
            send() {}
            resolveUser() {
              return null;
            }
          }
          registry.registerHandler('magicLink', new MagicLinkMailer());
        },
      };

      const moduleRef = await start([AuthenticationModule.forRoot({ magicLink: { url: 'https://example.com/magic' } })], [
        answering('api', 1),
        HeaderAuth,
        handlers,
      ]);

      expect(log.mock.calls.map(([message]: unknown[]) => message)).toContain(
        'AuthenticationRegistry: providers HeaderAuth, ApiAuth; handlers MagicLinkMailer (magicLink)',
      );
      expect(warn).not.toHaveBeenCalled();
      await moduleRef.close();
    });

    it('warns when no provider registered: every route that is not @Public() answers 401', async () => {
      const moduleRef = await start([AuthenticationModule.forRoot()]);

      expect(warn.mock.calls.map(([message]: unknown[]) => message)).toEqual([
        'AuthenticationRegistry: no credential provider is registered, so every route that is not @Public() answers 401. ' +
          'Register one from its constructor: `registry.registerProvider(this)`.',
      ]);
      expect(log.mock.calls.map(([message]: unknown[]) => message)).toContain('AuthenticationRegistry: no providers');
      await moduleRef.close();
    });
  });
});

describe('startup checks', () => {
  @Injectable()
  class JwtAuth extends JwtBearerProvider<{ id: string }> {
    constructor(registry: AuthenticationRegistry) {
      super();
      registry.registerProvider(this);
    }
    validate(claims: JwtClaims) {
      return { id: claims.sub! };
    }
  }

  const start = async (authentication: ReturnType<typeof AuthenticationModule.forRoot>, providers: Provider[] = []) => {
    const moduleRef = await Test.createTestingModule({ imports: [authentication], providers }).compile();
    await moduleRef.init();
    return moduleRef;
  };
  const magicLinks: Provider = {
    provide: 'MAGIC_LINKS',
    inject: [AuthenticationRegistry],
    useFactory: (registry: AuthenticationRegistry) => registry.registerHandler('magicLink', { send() {}, resolveUser: () => null }),
  };

  it('a JwtBearerProvider without a key fails at startup, naming `accessToken`', async () => {
    await expect(start(AuthenticationModule.forRoot(), [JwtAuth])).rejects.toThrow(
      /JwtAuth: nothing to verify tokens with. Configure `accessToken`/,
    );
    const ok = await start(AuthenticationModule.forRoot({ accessToken: { key: 's'.repeat(32) } }), [JwtAuth]);
    await ok.close();
  });

  it('invalid durations and keys fail at startup', async () => {
    await expect(start(AuthenticationModule.forRoot({ session: { idleTtl: '3 days' as never } }))).rejects.toThrow(
      /Invalid duration "3 days"/,
    );
    await expect(
      start(AuthenticationModule.forRoot({ mfa: { encryption: false, pendingTtl: '10 minutes' as never } })),
    ).rejects.toThrow(/Invalid duration "10 minutes"/);
    await expect(start(AuthenticationModule.forRoot({ accessToken: { key: 'short' } }))).rejects.toThrow(/HS256/);
  });

  it('a magic-link option without `url` fails at startup', async () => {
    await expect(start(AuthenticationModule.forRoot({ magicLink: {} as never }), [magicLinks])).rejects.toThrow(
      /`magicLink.url` is required/,
    );
  });

  it('values that arrive undefined from the environment fail at startup, naming the option', async () => {
    const unset = process.env.AUTH_TEST_UNSET_VARIABLE; // what `process.env.JWT_SECRET!` yields when nobody set it
    const forRoot = (options: AuthenticationModuleOptions) => start(AuthenticationModule.forRoot(options));

    await expect(forRoot({ accessToken: { key: unset! } })).rejects.toThrow(
      'AuthenticationModule: `accessToken.key` is required (a secret of at least 32 bytes or a KeyObject), but it is ' +
        'undefined: is the environment variable it reads set?',
    );
    await expect(forRoot({ accessToken: { key: '' } })).rejects.toThrow('`accessToken.key` is required (a secret of at least 32 bytes or a KeyObject), but it is empty');

    await expect(forRoot({ mfa: { encryption: { keys: [unset!] } } })).rejects.toThrow(
      '`mfa.encryption.keys[0]` is required (32 random bytes, or a random string of at least 32 characters), but it is undefined',
    );

    const callbackUrl = 'https://example.com/auth/oidc/:provider/callback';
    await expect(forRoot({ oidc: { callbackUrl, providers: { google: google({ clientId: unset!, clientSecret: 's' }) } } })).rejects.toThrow(
      '`oidc.providers.google.clientId` is required (the client id the provider issued), but it is undefined',
    );
    await expect(forRoot({ oidc: { callbackUrl, providers: { google: google({ clientId: 'c', clientSecret: unset! }) } } })).rejects.toThrow(
      "`oidc.providers.google.clientSecret` is required (the client secret the provider issued; a public client sets `tokenEndpointAuthMethod: 'none'` instead), but it is undefined",
    );

    // A template string over an unset variable is not undefined, but no URL either.
    await expect(forRoot({ magicLink: { url: `${unset}/sign-in/magic` } })).rejects.toThrow(
      'AuthenticationModule: `magicLink.url` must be an absolute http(s) URL (the page that receives the link). Got ' +
        '"undefined/sign-in/magic": is the environment variable it reads set?',
    );
    await expect(forRoot({ emailVerification: { url: unset! } })).rejects.toThrow('`emailVerification.url` is required (the page that receives the link), but it is undefined');
    await expect(forRoot({ passwordReset: { url: '/reset-password' } })).rejects.toThrow(
      '`passwordReset.url` must be an absolute http(s) URL (the page that receives the link). Got "/reset-password".',
    );
  });

  it("a feature's option without its handler fails at startup, and so does a handler without its option", async () => {
    await expect(start(AuthenticationModule.forRoot({ magicLink: { url: 'https://example.com/magic' } }))).rejects.toThrow(
      'AuthenticationModule: `magicLink` is configured, but no MagicLinkHandler is registered.',
    );
    await expect(
      start(
        AuthenticationModule.forRootAsync({
          useFactory: () => ({ oidc: { callbackUrl: 'https://example.com/auth/oidc/:provider/callback', providers: {} } }),
        }),
      ),
    ).rejects.toThrow('AuthenticationModule: `oidc` is configured, but no OidcAccountResolver is registered.');
    await expect(start(AuthenticationModule.forRoot(), [magicLinks])).rejects.toThrow(
      'AuthenticationModule: an object is registered as the `magicLink` handler, but the `magicLink` option is missing.',
    );
  });

  it('options that do not exist fail at startup instead of being ignored: classes, switches in the factory, typos', async () => {
    const forRoot = (options: object) => start(AuthenticationModule.forRoot(options as AuthenticationModuleOptions));
    const factoryReturns = (options: object) =>
      start(AuthenticationModule.forRootAsync({ useFactory: () => options as AuthenticationModuleOptions }));

    await expect(forRoot({ providers: [HeaderAuth] })).rejects.toThrow(
      'AuthenticationModule: `providers` is not an option: credential providers register themselves: provide the class in one of ' +
        'your modules, and call `registry.registerProvider(this, { order })` from its constructor',
    );

    await expect(factoryReturns({ magicLinkHandler: {} })).rejects.toThrow(
      "`magicLinkHandler` is not an option: handlers register themselves: `registry.registerHandler('magicLink', this)`",
    );
    await expect(factoryReturns({ globalGuard: false })).rejects.toThrow(
      '`globalGuard` is in the options the factory returned. It goes at the top level of forRootAsync(), next to useFactory',
    );

    await expect(forRoot({ sessions: {} })).rejects.toThrow('AuthenticationModule: `sessions` is not an option. The options are session, ');
  });
});

describe('numeric lifetimes that look like seconds', () => {
  let warn: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => warn.mockRestore());

  const compile = async (authentication: ReturnType<typeof AuthenticationModule.forRoot>) => {
    const moduleRef = await Test.createTestingModule({ imports: [authentication] }).compile();
    await moduleRef.close();
  };

  it('warn at startup, one per lifetime under a minute, suggesting the string form', async () => {
    await compile(
      AuthenticationModule.forRootAsync({
        useFactory: () => ({
          accessToken: { key: 's'.repeat(32), ttl: 3600 }, // the hour of JwtModule's `expiresIn: 3600`
          refreshToken: { ttl: 90 },
          session: { absoluteTtl: 1800, idleTtl: 0 }, // `0` turns the idle timeout off: no warning
          mfa: { encryption: false, pendingTtl: 600 },
        }),
      }),
    );

    const advice = 'Numeric lifetimes are milliseconds, not seconds as in @nestjs/jwt';
    expect(warn.mock.calls.map(([message]: unknown[]) => message)).toEqual([
      `\`accessToken.ttl\` is 3600 milliseconds. ${advice}: did you mean '1h'?`,
      `\`refreshToken.ttl\` is 90 milliseconds. ${advice}: did you mean '90s'?`,
      `\`session.absoluteTtl\` is 1800 milliseconds. ${advice}: did you mean '30m'?`,
      `\`mfa.pendingTtl\` is 600 milliseconds. ${advice}: did you mean '10m'?`,
    ]);
    expect(warn.mock.contexts[0]).toMatchObject({ context: 'AuthenticationModule' });
  });

  it('stay quiet for strings, and for a minute or more', async () => {
    await compile(
      AuthenticationModule.forRoot({
        accessToken: { key: 's'.repeat(32), ttl: '15m' },
        refreshToken: { ttl: 60_000, absoluteTtl: '90d' },
        session: { idleTtl: 0 },
      }),
    );

    expect(warn).not.toHaveBeenCalled();
  });
});

/**
 * Calls `next.handle()` only when subscribed, once per attempt, as
 * `@nestjs/resilience`'s interceptor does: the handler runs in the async
 * context of that later call, not of the global interceptors' `intercept()`.
 */
@Injectable()
class RetryOnceInterceptor implements NestInterceptor {
  intercept(_context: ExecutionContext, next: CallHandler) {
    return defer(() => next.handle()).pipe(retry({ count: 1, delay: 5 }));
  }
}

@Controller('flaky')
@UseInterceptors(RetryOnceInterceptor)
class FlakyController {
  private attempts = 0;
  constructor(private readonly auth: AuthenticationContext<{ id: string }>) {}

  @Get()
  whoAmI() {
    const id = this.auth.requireUser().id;
    if (++this.attempts === 1) {
      throw new ServiceUnavailableException();
    }
    return { id, attempts: this.attempts };
  }
}

describe.each(adapters.map((a) => a.name))('AuthenticationContext under an interceptor that subscribes later (%s)', (adapter) => {
  let app: INestApplication;
  afterEach(() => app.close());

  it('holds the user in every attempt the inner interceptor runs', async () => {
    @Module({ imports: [AuthenticationModule.forRoot()], controllers: [FlakyController], providers: [HeaderAuth] })
    class AppModule {}
    app = await createApp(adapter, AppModule);

    await request(app.getHttpServer()).get('/flaky').set('X-User', 'u1').expect(200, { id: 'u1', attempts: 2 });
  });
});
