/**
 * The storage registry: how apps register their stores (`AuthenticationStorage.registerSource()`
 * from a provider's constructor), and every hardening rule of CONVENTIONS.md rule 2.
 */
import { Controller, Get, Injectable, Logger, Module, Scope, type INestApplicationContext } from '@nestjs/common';
import { LazyModuleLoader } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { createApp } from './support/adapters.js';
import {
  AuthenticationModule,
  AuthenticationRegistry,
  AuthenticationStorage,
  InMemoryEmailTokenStore,
  InMemoryMfaStore,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  JwtBearerProvider,
  SessionCookieProvider,
  SessionService,
  TokenService,
  type JwtClaims,
  type MfaStore,
  type SessionRecord,
} from '../lib/index.js';
import { LOCK_STORAGE } from '../lib/storage/authentication.storage.js';

@Injectable()
class Sessions extends SessionCookieProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return { id: session.userId };
  }
}

@Injectable()
class Bearer extends JwtBearerProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this, { order: 1 });
  }
  validate(claims: JwtClaims) {
    return { id: claims.sub! };
  }
}

/** What an app writes: an ordinary provider that registers itself. */
@Injectable()
class RedisSessionStore extends InMemorySessionStore {
  constructor(storage: AuthenticationStorage) {
    super();
    storage.registerSource({ sessions: this });
  }
}

/** One provider, several contracts (in-memory stores stand in for the database). */
@Injectable()
class SqlAuthenticationStore extends InMemoryRefreshTokenStore implements MfaStore {
  private readonly totp = new InMemoryMfaStore();
  constructor(storage: AuthenticationStorage) {
    super();
    storage.registerSource({ refreshTokens: this, mfa: this });
  }
  getTotp: MfaStore['getTotp'] = (...args) => this.totp.getTotp(...args);
  saveTotp: MfaStore['saveTotp'] = (...args) => this.totp.saveTotp(...args);
  claimTotpStep: MfaStore['claimTotpStep'] = (...args) => this.totp.claimTotpStep(...args);
  saveRecoveryCodes: MfaStore['saveRecoveryCodes'] = (...args) => this.totp.saveRecoveryCodes(...args);
  consumeRecoveryCode: MfaStore['consumeRecoveryCode'] = (...args) => this.totp.consumeRecoveryCode(...args);
  countRecoveryCodes: MfaStore['countRecoveryCodes'] = (...args) => this.totp.countRecoveryCodes(...args);
  recordMfaFailure: MfaStore['recordMfaFailure'] = (...args) => this.totp.recordMfaFailure(...args);
  countMfaFailures: MfaStore['countMfaFailures'] = (...args) => this.totp.countMfaFailures(...args);
  clearMfaFailures: MfaStore['clearMfaFailures'] = (...args) => this.totp.clearMfaFailures(...args);
}

const KEY = 's'.repeat(32);
/** A magic-link handler, registered the way an app's own is. */
@Injectable()
class MagicLinks {
  constructor(registry: AuthenticationRegistry) {
    registry.registerHandler('magicLink', { send() {}, resolveUser: () => null });
  }
}

async function start(imports: unknown[], providers: unknown[] = []) {
  const moduleRef = await Test.createTestingModule({ imports: imports as never[], providers: providers as never[] }).compile();
  await moduleRef.init();
  return moduleRef;
}

describe('AuthenticationStorage.registerSource()', () => {
  const store = () => new InMemorySessionStore();

  it('checks the shape at once, naming the class, the contract and the missing methods', () => {
    const storage = new AuthenticationStorage();
    class HalfStore {
      getSession() {}
      createSession() {}
    }

    expect(() => storage.registerSource({ sessions: new HalfStore() as never })).toThrow(
      "AuthenticationStorage.registerSource(): HalfStore doesn't implement SessionStore for `sessions`: touchSession(), " +
        'deleteSession(), listUserSessions(), deleteUserSessions() are missing.',
    );
    expect(() => storage.registerSource({ mfa: store() as never })).toThrow("InMemorySessionStore doesn't implement MfaStore for `mfa`");

    expect(() => storage.registerSource({ sessions: undefined })).toThrow(
      'AuthenticationStorage.registerSource(): expected an object implementing SessionStore as `sessions`, got undefined.',
    );
    expect(() => storage.registerSource({ sessions: InMemorySessionStore as never })).toThrow(
      'got the class InMemorySessionStore (pass an instance).',
    );
    expect(() => storage.registerSource(null as never)).toThrow('AuthenticationStorage.registerSource(): the contracts go by name, and got null.');
  });

  it('takes the contracts by name: a store passed as itself, or a misspelled contract, fails', () => {
    const storage = new AuthenticationStorage();

    expect(() => storage.registerSource(store() as never)).toThrow(
      'AuthenticationStorage.registerSource(): the contracts go by name, and InMemorySessionStore was passed as ' +
        'itself. Name what it implements: `registerSource({ sessions: this })`.',
    );
    expect(() => storage.registerSource({})).toThrow('AuthenticationStorage.registerSource(): the contracts go by name, and got none.');
    expect(() => storage.registerSource({ sessions: store(), session: store() } as never)).toThrow(
      'unknown contract `session`. The contracts are sessions (SessionStore), refreshTokens (RefreshTokenStore), ' +
        'mfa (MfaStore), magicLinks (MagicLinkStore), oidcStates (OidcStateStore), emailTokens (EmailTokenStore).',
    );
  });

  it('refuses a second source for a contract, naming both, unless `replace` is set', () => {
    const storage = new AuthenticationStorage();
    const first = new RedisSessionStore(storage);
    class DrizzleSessionStore extends InMemorySessionStore {}

    expect(() => storage.registerSource({ sessions: new DrizzleSessionStore() })).toThrow(
      "AuthenticationStorage.registerSource(): DrizzleSessionStore can't register `sessions`, RedisSessionStore already " +
        'did. Register each contract once, or pass { replace: true } to replace it on purpose (tests, wrappers).',
    );
    expect(() => storage.registerSource({ sessions: first })).toThrow(
      "RedisSessionStore can't register `sessions`, it already did (the same instance, twice).",
    );

    const fake = store();
    storage.registerSource({ sessions: fake }, { replace: true });
    storage[LOCK_STORAGE]({ log: false });
    expect(storage.sessions).toBe(fake);
    expect(storage.sessions).not.toBe(first);
  });

  it('changes nothing when one of the stores is refused', () => {
    const storage = new AuthenticationStorage();
    expect(() => storage.registerSource({ sessions: store(), mfa: {} as never })).toThrow('MfaStore');

    const sessions = store();
    storage.registerSource({ sessions }); // no "already registered": the refused call registered nothing
    storage[LOCK_STORAGE]({ log: false });
    expect(storage.sessions).toBe(sessions);
    expect(storage.mfa).toBeInstanceOf(InMemoryMfaStore);
  });

  it('serves the in-memory default for a contract nobody registered, the same instance every time', () => {
    const storage = new AuthenticationStorage();
    expect(storage.emailTokens).toBeInstanceOf(InMemoryEmailTokenStore);
    expect(storage.emailTokens).toBe(storage.emailTokens);
  });

  it('locks at the first read too (another module’s hook may read first): later registrations throw', () => {
    const storage = new AuthenticationStorage();
    void storage.sessions;

    expect(() => new RedisSessionStore(storage)).toThrow(
      'AuthenticationStorage.registerSource(): RedisSessionStore (sessions) registered after AuthenticationModule ' +
        'initialized (or after its storage was first read), which already uses in-memory stores (the default: state is ' +
        'lost on restart and not shared between instances). Register from the constructor of a singleton provider: ' +
        'providers of lazy-loaded modules, request-scoped and transient providers, and lifecycle hooks run too late.',
    );
    expect(() => storage.registerSource({ sessions: store() }, { replace: true })).toThrow('registered after AuthenticationModule initialized');
  });

  it('keeps the lock internal: no public lock(), and locking again changes nothing', () => {
    const storage = new AuthenticationStorage();
    expect('lock' in storage).toBe(false);

    const sessions = store();
    storage.registerSource({ sessions });
    storage[LOCK_STORAGE]({ log: false });
    storage[LOCK_STORAGE]();
    expect(storage.sessions).toBe(sessions);
  });
});

describe('AuthenticationStorage in an app', () => {
  let log: ReturnType<typeof vi.spyOn>;
  let moduleRef: INestApplicationContext | undefined;
  beforeEach(() => {
    log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });
  afterEach(async () => {
    log.mockRestore();
    await moduleRef?.close();
    moduleRef = undefined;
  });
  const logged = () =>
    log.mock.calls
      .filter((_: unknown, i: number) => log.mock.contexts[i]?.context === 'AuthenticationModule')
      .map(([message]: unknown[]) => message)
      .filter((message: unknown) => String(message).startsWith('AuthenticationStorage:'));

  it('uses the store a provider registered from its constructor, and logs it at startup', async () => {
    @Module({ providers: [RedisSessionStore] })
    class RedisModule {}
    moduleRef = await start([AuthenticationModule.forRoot(), RedisModule], [Sessions]);

    const { session } = await moduleRef.get(SessionService).create('u1');
    await expect(moduleRef.get(RedisSessionStore).getSession(session.id)).resolves.toMatchObject({ userId: 'u1' });
    expect(moduleRef.get(AuthenticationStorage).sessions).toBe(moduleRef.get(RedisSessionStore));

    // Without `mfa` and `accessToken`, a session cookie reads no authenticators and revokes no refresh tokens.
    expect(logged()).toEqual(['AuthenticationStorage: RedisSessionStore (sessions)']);
  });

  it('splits the contracts between providers, each used for its own; the rest stay in memory', async () => {
    @Module({ providers: [RedisSessionStore, SqlAuthenticationStore] })
    class StoresModule {}
    moduleRef = await start([
      AuthenticationModule.forRoot({
        accessToken: { key: KEY },
        mfa: { encryption: false },
        magicLink: { url: 'https://example.com/magic' },
      }),
      StoresModule,
    ], [Sessions, Bearer, MagicLinks]);

    const sql = moduleRef.get(SqlAuthenticationStore);
    const storage = moduleRef.get(AuthenticationStorage);
    expect([storage.sessions, storage.refreshTokens, storage.mfa]).toEqual([moduleRef.get(RedisSessionStore), sql, sql]);

    const pair = await moduleRef.get(TokenService).issue('u1');
    expect(pair.refreshToken).toBeTruthy();

    expect(logged()).toEqual([
      'AuthenticationStorage: RedisSessionStore (sessions); SqlAuthenticationStore (refreshTokens, mfa); in-memory (magicLinks)',
    ]);
  });

  it('fails at startup when two providers register the same contract, naming both', async () => {
    @Injectable()
    class DrizzleSessionStore extends InMemorySessionStore {
      constructor(storage: AuthenticationStorage) {
        super();
        storage.registerSource({ sessions: this });
      }
    }
    @Module({ providers: [RedisSessionStore, DrizzleSessionStore] })
    class StoresModule {}

    await expect(start([AuthenticationModule.forRoot(), StoresModule])).rejects.toThrow(
      /(Drizzle|Redis)SessionStore can't register `sessions`, (Redis|Drizzle)SessionStore already did/,
    );
  });

  it('locks in the module’s onModuleInit: a lazy-loaded module’s store registers too late, and throws', async () => {
    @Module({ providers: [RedisSessionStore] })
    class LazyStoreModule {}
    moduleRef = await start([AuthenticationModule.forRoot()]);

    await expect(moduleRef.get(LazyModuleLoader).load(() => LazyStoreModule)).rejects.toThrow(
      'AuthenticationStorage.registerSource(): RedisSessionStore (sessions) registered after AuthenticationModule initialized',
    );
    expect(moduleRef.get(AuthenticationStorage).sessions).toBeInstanceOf(InMemorySessionStore);
  });

  it('a request-scoped store registers too late: the request fails instead of switching stores', async () => {
    @Injectable({ scope: Scope.REQUEST })
    class PerRequestStore extends RedisSessionStore {}
    @Controller('scoped')
    class ScopedController {
      constructor(readonly store: PerRequestStore) {}
      @Get()
      get() {
        return {};
      }
    }
    @Module({ imports: [AuthenticationModule.forRoot({ globalGuard: false })], controllers: [ScopedController], providers: [PerRequestStore] })
    class AppModule {}

    const errors = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    const app = await createApp('express', AppModule);

    try {
      await request(app.getHttpServer()).get('/scoped').expect(500);
      expect(String(errors.mock.calls[0]?.[0])).toContain('registered after AuthenticationModule initialized');
    } finally {
      errors.mockRestore();
      await app.close();
    }
  });

  it('overrideProvider(store).useValue(inMemory) in a test: the plain instance does not register, the defaults apply', async () => {
    @Module({ providers: [RedisSessionStore] })
    class RedisModule {}
    const replacement = new InMemorySessionStore();
    const compiled = await Test.createTestingModule({ imports: [AuthenticationModule.forRoot(), RedisModule] })
      .overrideProvider(RedisSessionStore)
      .useValue(replacement)
      .compile();
    moduleRef = await compiled.init();

    const active = moduleRef.get(AuthenticationStorage).sessions;
    expect(active).toBeInstanceOf(InMemorySessionStore);
    expect(active).not.toBe(replacement);
    expect(logged()).toEqual(['AuthenticationStorage: in-memory stores (the default: state is lost on restart and not shared between instances)']);
  });

  it('registerSource(fake, { replace: true }) between compile() and init() swaps the app’s store in a test', async () => {
    @Module({ providers: [RedisSessionStore] })
    class RedisModule {}
    const compiled = await Test.createTestingModule({ imports: [AuthenticationModule.forRoot(), RedisModule], providers: [Sessions] }).compile();

    const fake = new InMemorySessionStore();
    compiled.get(AuthenticationStorage).registerSource({ sessions: fake }, { replace: true });
    moduleRef = await compiled.init();

    const { session } = await moduleRef.get(SessionService).create('u1');
    await expect(fake.getSession(session.id)).resolves.toMatchObject({ userId: 'u1' });
    expect(logged()).toEqual(['AuthenticationStorage: InMemorySessionStore (sessions)']);
  });
});

describe('the production guard', () => {
  const env = process.env.NODE_ENV;
  let log: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    process.env.NODE_ENV = 'production';
    log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });
  afterEach(() => {
    process.env.NODE_ENV = env;
    log.mockRestore();
  });

  it('fails at startup naming each contract in use without a store, and how to register one', async () => {
    await expect(
      start([AuthenticationModule.forRoot({ accessToken: { key: KEY }, mfa: { encryption: false } })], [Sessions]),
    ).rejects.toThrow(
      'AuthenticationStorage: no store is registered for `sessions` (SessionStore), `refreshTokens` (RefreshTokenStore), ' +
        'and `mfa` (MfaStore), and NODE_ENV is "production": in memory, sessions, refresh tokens, and authenticators and ' +
        'recovery codes would be lost on restart and not shared between instances. Implement SessionStore, ' +
        'RefreshTokenStore, and MfaStore in a provider that injects AuthenticationStorage and calls ' +
        '`storage.registerSource({ sessions: this, refreshTokens: this, mfa: this })` in its constructor, or set ' +
        '`allowInMemoryStorage: true` in the AuthenticationModule options to run in memory anyway.',
    );
  });

  it('checks only the contracts the configured features use', async () => {
    // A bearer-token API: no session cookie, so no session store; no `mfa`, so no authenticator check.
    await expect(start([AuthenticationModule.forRoot({ accessToken: { key: KEY } })], [Bearer])).rejects.toThrow(
      'no store is registered for `refreshTokens` (RefreshTokenStore), and NODE_ENV',
    );

    @Module({ providers: [SqlAuthenticationStore] })
    class SqlModule {}
    const api = await start([AuthenticationModule.forRoot({ accessToken: { key: KEY } }), SqlModule], [Bearer]);
    await api.close();

    // Magic links sign browsers in: sessions and pending links.
    await expect(
      start([AuthenticationModule.forRoot({ magicLink: { url: 'https://example.com/magic' } }), SqlModule], [MagicLinks]),
    ).rejects.toThrow('no store is registered for `sessions` (SessionStore) and `magicLinks` (MagicLinkStore), and NODE_ENV');
  });

  it('starts once every contract in use has a store, or with allowInMemoryStorage', async () => {
    @Module({ providers: [RedisSessionStore, SqlAuthenticationStore] })
    class StoresModule {}
    const options = { accessToken: { key: KEY }, mfa: { encryption: false as const } };

    const stored = await start([AuthenticationModule.forRoot(options), StoresModule], [Sessions]);
    await stored.close();

    const allowed = await start(
      [
        AuthenticationModule.forRootAsync({
          useFactory: () => ({ accessToken: { key: KEY }, mfa: { encryption: false }, allowInMemoryStorage: true }),
        }),
      ],
      [Sessions],
    );
    await allowed.close();

    expect(log.mock.calls.map(([message]: unknown[]) => message)).toContain(
      'AuthenticationStorage: in-memory stores (the default: state is lost on restart and not shared between instances)',
    );
  });

  it('takes NODE_ENV as production whatever its case, and with stray spaces (a .env file)', async () => {
    for (const spelling of ['Production', 'PRODUCTION', 'production ', ' production\n']) {
      process.env.NODE_ENV = spelling;
      await expect(start([AuthenticationModule.forRoot({ accessToken: { key: KEY } })], [Bearer])).rejects.toThrow(
        'no store is registered for `refreshTokens` (RefreshTokenStore), and NODE_ENV',
      );
    }
  });

  it('stays out of the way outside production', async () => {
    process.env.NODE_ENV = 'development';
    const dev = await start([AuthenticationModule.forRoot({ accessToken: { key: KEY } })], [Sessions]);
    await dev.close();
  });
});

describe('the removed `stores` option', () => {
  it('fails at startup wherever it is set, instead of silently running in memory', async () => {
    const message =
      'AuthenticationModule: `stores` is not an option: storage is registered by a provider: implement the store ' +
      'interfaces in an @Injectable() class and call `storage.registerSource({ sessions: this, … })` from its constructor';

    await expect(start([AuthenticationModule.forRoot({ stores: { session: InMemorySessionStore } } as never)])).rejects.toThrow(message);
    await expect(start([AuthenticationModule.forRootAsync({ useFactory: () => ({ stores: {} }) as never })])).rejects.toThrow(message);
  });
});
