/**
 * Which storage contracts each feature reads and writes, and the production guard that
 * follows from it: at startup, every contract a configured feature uses must have a
 * registered store; at run time, a read of any other contract without one fails instead
 * of running on the in-memory default. The family example's finding 8 is the case this
 * file was written for; since #20, MFA and refresh tokens are off unless configured, so
 * the apps sharing a user database have to configure them alike.
 */
import { Injectable, Logger, Module, type INestApplicationContext, type Provider } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/internal';
import { Test } from '@nestjs/testing';
import { CONTRACTS_BY_FEATURE } from '../lib/storage/authentication.storage.js';
import {
  AuthenticationError,
  AuthenticationModule,
  AuthenticationRegistry,
  AuthenticationStorage,
  EmailVerificationHandler,
  EmailVerificationService,
  InMemoryEmailTokenStore,
  InMemoryMagicLinkStore,
  InMemoryMfaStore,
  InMemoryOidcStateStore,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  JwtBearerProvider,
  MagicLinkHandler,
  MagicLinkService,
  MfaService,
  OidcAccountResolver,
  OidcService,
  PasswordResetHandler,
  PasswordResetService,
  SessionCookieProvider,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationHandlers,
  type AuthenticationModuleOptions,
  type AuthenticationProvider,
  type AuthenticationStorageContract,
  type AuthenticationStorageSources,
  type JwtClaims,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp, totpStep } from '../lib/mfa/otp.util.js';
import { authenticationStoreContract } from '../lib/testing/index.js';
import { MockOidcProvider } from './mock-oidc.js';

@Injectable()
class Bearer extends JwtBearerProvider<{ id: string }> {
  validate(claims: JwtClaims) {
    return { id: claims.sub! };
  }
}

@Injectable()
class Sessions extends SessionCookieProvider<{ id: string }> {
  validate(session: SessionRecord) {
    return { id: session.userId };
  }
}

const KEY = 's'.repeat(32);
const CONTRACTS: AuthenticationStorageContract[] = ['sessions', 'refreshTokens', 'mfa', 'magicLinks', 'oidcStates', 'emailTokens'];

/**
 * The database every instance of the app shares, as in-memory stores behind
 * proxies that record which contracts were called.
 */
class World {
  readonly touched = new Set<AuthenticationStorageContract>();
  readonly sessions = this.track('sessions', new InMemorySessionStore());
  readonly refreshTokens = this.track('refreshTokens', new InMemoryRefreshTokenStore());
  readonly mfa = this.track('mfa', new InMemoryMfaStore());
  readonly magicLinks = this.track('magicLinks', new InMemoryMagicLinkStore());
  readonly oidcStates = this.track('oidcStates', new InMemoryOidcStateStore());
  readonly emailTokens = this.track('emailTokens', new InMemoryEmailTokenStore());

  private track<T extends object>(contract: AuthenticationStorageContract, store: T): T {
    return new Proxy(store, {
      get: (target, key) => {
        const value = Reflect.get(target, key, target);
        if (typeof value !== 'function') {
          return value;
        }

        return (...args: unknown[]) => {
          this.touched.add(contract);
          return value.apply(target, args);
        };
      },
    });
  }
}

/** A provider that registers the world's stores for `contracts`, and nothing else. */
function storesFor(world: World, contracts: readonly AuthenticationStorageContract[]) {
  @Injectable()
  class PartialStore {
    constructor(storage: AuthenticationStorage) {
      const sources: AuthenticationStorageSources = {};
      for (const contract of contracts) {
        (sources as Record<string, unknown>)[contract] = world[contract];
      }

      if (contracts.length > 0) {
        storage.registerSource(sources);
      }
    }
  }

  @Module({ providers: [PartialStore] })
  class StoresModule {}
  return StoresModule;
}

/** The contracts a production startup failure names, from the call it suggests: `registerSource({ a: this, b: this })`. */
function named(error: unknown): string[] {
  const call = /registerSource\(\{ (.*?) \}\)/.exec((error as Error).message)?.[1];
  if (!call) {
    throw error;
  }
  return call.split(', ').map((entry) => entry.replace(': this', ''));
}

/** A configuration: the options, and the providers and handlers the app registers (instances, in order). */
interface Setup {
  options?: AuthenticationModuleOptions;
  providers?: AuthenticationProvider<any, any>[];
  handlers?: Partial<AuthenticationHandlers>;
}

async function start({ options = {}, providers = [], handlers = {} }: Setup, stores: unknown): Promise<INestApplicationContext> {
  const register: Provider = {
    provide: 'REGISTER',
    inject: [AuthenticationRegistry],
    useFactory: (registry: AuthenticationRegistry) => {
      providers.forEach((provider, order) => registry.registerProvider(provider, { order }));
      for (const [feature, handler] of Object.entries(handlers)) {
        registry.registerHandler(feature as keyof AuthenticationHandlers, handler as never);
      }
    },
  };

  const moduleRef = await Test.createTestingModule({
    imports: [AuthenticationModule.forRoot(options), stores as never],
    providers: [register],
  }).compile();
  await moduleRef.init();
  return moduleRef;
}

/** The family example's authentication: a bearer-token API with password reset and email verification, no `mfa`. */
class ResetMailer extends PasswordResetHandler {
  findUser() {
    return null;
  }
  send() {}
  updatePassword() {}
}
class VerificationMailer extends EmailVerificationHandler {
  send() {}
  markVerified() {
    return true;
  }
}
const FAMILY = (): Setup => ({
  providers: [new Bearer()],
  handlers: { passwordReset: new ResetMailer(), emailVerification: new VerificationMailer() },
  options: {
    accessToken: { key: KEY },
    passwordReset: { url: 'https://example.com/reset' },
    emailVerification: { url: 'https://example.com/verify' },
  },
});

describe('the production guard and what the features read', () => {
  const env = process.env.NODE_ENV;
  let moduleRef: INestApplicationContext | undefined;
  beforeEach(() => {
    process.env.NODE_ENV = 'production';
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });
  afterEach(async () => {
    await moduleRef?.close();
    moduleRef = undefined;
    process.env.NODE_ENV = env;
    vi.restoreAllMocks();
  });

  /**
   * The family example's finding 8, under the rule of #20: MFA is off unless `mfa` is
   * configured. Alice enrolled an authenticator through another instance (one configured
   * with `mfa`), so the shared database has her confirmed authenticator. This instance has
   * no `mfa` option: it neither asks for an `MfaStore` nor reads one, and signs her in with
   * her password alone. Apps sharing a user database must configure `mfa` alike.
   */
  it('without `mfa`, signs in with a password alone a user who enrolled an authenticator through another instance', async () => {
    const world = new World();
    await world.mfa.saveTotp('alice', { secret: 'sealed-by-another-instance', confirmed: true });
    world.touched.clear();

    moduleRef = await start(FAMILY(), storesFor(world, ['sessions', 'refreshTokens', 'emailTokens']));
    await expect(moduleRef.get(TokenService).issue('alice', { method: 'password' })).resolves.toMatchObject({ expiresIn: 900 });
    expect(world.touched.has('mfa')).toBe(false);
  });

  it('without `mfa`, a session cookie app gives such a user a session with no pending second factor', async () => {
    const world = new World();
    await world.mfa.saveTotp('alice', { secret: 'sealed-by-another-instance', confirmed: true });
    world.touched.clear();

    moduleRef = await start({ providers: [new Sessions()] }, storesFor(world, ['sessions']));
    const { session } = await moduleRef.get(SignInService).signIn('alice');
    expect(session.mfa).toBeUndefined();
    expect([...world.touched]).toEqual(['sessions']);
  });

  it('with `mfa`, every sign-in sees an authenticator enrolled through another instance', async () => {
    const world = new World();
    await world.mfa.saveTotp('alice', { secret: 'sealed-by-another-instance', confirmed: true });

    moduleRef = await start(
      { providers: [new Sessions(), new Bearer()], options: { accessToken: { key: KEY }, mfa: { encryption: false } } },
      storesFor(world, ['sessions', 'refreshTokens', 'mfa']),
    );
    expect((await moduleRef.get(SignInService).signIn('alice')).session.mfa).toBe('pending');
    await expect(moduleRef.get(TokenService).issue('alice')).rejects.toMatchObject({ code: 'mfa_required' });
  });

  describe('the contracts each feature uses', () => {
    const magicLinks: string[] = [];
    const resetLinks: string[] = [];
    const verificationLinks: string[] = [];
    const tokenOf = (links: string[]) => new URL(links.at(-1)!).searchParams.get('token')!;

    class Links extends MagicLinkHandler {
      send({ url }: { url: string }) {
        magicLinks.push(url);
      }
      resolveUser(email: string) {
        return { id: email.split('@')[0]!, email };
      }
    }
    class Resets extends PasswordResetHandler {
      findUser(email: string) {
        return { id: email.split('@')[0]!, email, passwordHash: null };
      }
      send({ url }: { url: string }) {
        resetLinks.push(url);
      }
      updatePassword() {}
    }
    class Verifications extends EmailVerificationHandler {
      send({ url }: { url: string }) {
        verificationLinks.push(url);
      }
      markVerified() {
        return true;
      }
    }
    class Accounts extends OidcAccountResolver {
      resolveUser() {
        return { id: 'u1' };
      }
    }

    const idp = new MockOidcProvider();
    beforeAll(() => idp.start());
    afterAll(() => idp.stop());

    /**
     * Per feature: its configuration alone, the contracts the production guard asks for
     * (written out here, not read from the mapping), and every flow of the feature.
     */
    const FEATURES: {
      feature: keyof typeof CONTRACTS_BY_FEATURE;
      options: () => Setup;
      contracts: AuthenticationStorageContract[];
      flows: (app: INestApplicationContext, world: World) => Promise<void>;
    }[] = [
      {
        feature: 'sessionCookie',
        options: () => ({ providers: [new Sessions()] }),
        contracts: ['sessions'],
        flows: async (app) => {
          const signIn = app.get(SignInService);
          const sessions = app.get(SessionService);

          const { token, session } = await signIn.signIn('u1');
          expect(session.mfa).toBeUndefined();
          expect(await sessions.validate(token)).toMatchObject({ userId: 'u1' });
          expect(await sessions.list('u1')).toHaveLength(1);

          const rotated = (await sessions.rotate(session))!;
          expect(await sessions.revoke(rotated.session.id, { userId: 'u1' })).toBe(true);
          const again = await signIn.signIn('u1');
          await signIn.signOutEverywhere('u1');
          expect(await sessions.validate(again.token)).toBeNull();
        },
      },
      {
        feature: 'refreshToken',
        options: () => ({ providers: [new Bearer()], options: { accessToken: { key: KEY } } }),
        contracts: ['refreshTokens'],
        flows: async (app) => {
          const tokens = app.get(TokenService);
          const pair = await tokens.issue('u1');
          const next = await tokens.refresh(pair.refreshToken);
          expect(await tokens.revoke(next.refreshToken)).toBe(true);
          await tokens.revokeAll('u1');
        },
      },
      {
        feature: 'mfa',
        options: () => ({ options: { mfa: { encryption: false } } }),
        contracts: ['mfa'],
        flows: async (app) => {
          const mfa = app.get(MfaService);
          const { secret } = await mfa.enroll('u1', 'u1@example.com');
          const code = hotp(base32Decode(secret), totpStep(Math.floor(Date.now() / 1000)));
          expect(await mfa.confirm('u1', code)).toBe(true);
          expect(await mfa.isEnrolled('u1')).toBe(true);
          expect(await mfa.verifyTotp('u1', 'not a code')).toBe(false);

          const [recovery] = await mfa.generateRecoveryCodes('u1');
          expect(await mfa.verifyRecoveryCode('u1', recovery!)).toBe(true);
          expect(await mfa.remainingRecoveryCodes('u1')).toBe(9);
          await mfa.disable('u1');
        },
      },
      {
        feature: 'magicLink',
        options: () => ({ handlers: { magicLink: new Links() }, options: { magicLink: { url: 'https://example.com/magic' } } }),
        contracts: ['sessions', 'magicLinks'],
        flows: async (app) => {
          const links = app.get(MagicLinkService);
          // Outside HTTP: the browser's transaction cookie is passed by hand.
          const browser = (cookie?: string) => ({ request: { headers: { cookie: cookie?.split(';')[0] } } });

          const first = await links.create('u1@example.com');
          expect(await links.consume(tokenOf(magicLinks), browser(first.cookie))).toMatchObject({ session: { userId: 'u1' } });
        },
      },
      {
        feature: 'oidc',
        options: () => ({
          handlers: { oidc: new Accounts() },
          options: {
            oidc: {
              callbackUrl: 'https://example.com/auth/oidc/:provider/callback',
              providers: { mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret } },
            },
          },
        }),
        contracts: ['sessions', 'oidcStates'],
        flows: async (app) => {
          const oidc = app.get(OidcService);
          const login = await oidc.start('mock', { request: { method: 'GET', headers: {} } });
          const state = new URL(login.url).searchParams.get('state')!;
          const code = idp.approve(login.url, { sub: 'alice-sub' });
          await oidc.finish('mock', { state, code }, { request: { method: 'GET', headers: { cookie: login.cookies[0].split(';')[0] } } });

          // Linking reads the session that asks for it.
          const { token } = await app.get(SignInService).signIn('u1');
          await oidc.start('mock', { link: true, request: { method: 'GET', headers: { cookie: `__Host-sid=${token}` } } });
        },
      },
      {
        feature: 'passwordReset',
        options: () => ({
          handlers: { passwordReset: new Resets() },
          options: { passwordReset: { url: 'https://example.com/reset' }, password: { logN: 10 } },
        }),
        contracts: ['sessions', 'emailTokens'],
        flows: async (app) => {
          const resets = app.get(PasswordResetService);

          resets.request('u1@example.com');
          await resets.onModuleDestroy();
          expect(await resets.reset(tokenOf(resetLinks), 'a new password')).toEqual({ userId: 'u1' });

          resets.request('u2@example.com');
          await resets.onModuleDestroy();
          const result = await resets.reset(tokenOf(resetLinks), 'a new password', { signIn: true });
          expect(result?.signedIn?.session).toMatchObject({ userId: 'u2' });
          expect(result?.signedIn?.session.mfa).toBeUndefined();
        },
      },
      {
        feature: 'emailVerification',
        options: () => ({
          handlers: { emailVerification: new Verifications() },
          options: { emailVerification: { url: 'https://example.com/verify' } },
        }),
        contracts: ['emailTokens'],
        flows: async (app) => {
          const verification = app.get(EmailVerificationService);
          await verification.send({ id: 'u1', email: 'u1@example.com' });
          expect(await verification.verify(tokenOf(verificationLinks))).toEqual({ userId: 'u1', email: 'u1@example.com' });
        },
      },
    ];

    it('lists every feature of the mapping', () => {
      expect(FEATURES.map(({ feature }) => feature).sort()).toEqual(Object.keys(CONTRACTS_BY_FEATURE).sort());
    });

    it.each(FEATURES)('$feature: startup fails naming exactly the contracts it uses', async ({ options, contracts }) => {
      const failure = start(options(), storesFor(new World(), []));
      await expect(failure).rejects.toThrow('and NODE_ENV is "production"');
      expect(named(await failure.catch((error: unknown) => error))).toEqual(contracts);
    });

    it.each(FEATURES)(
      '$feature: every flow runs with only those contracts registered, and touches each of them',
      async ({ options, contracts, flows }) => {
        const world = new World();
        moduleRef = await start(options(), storesFor(world, contracts));
        await flows(moduleRef, world);
        expect(CONTRACTS.filter((contract) => world.touched.has(contract))).toEqual(contracts);
      },
    );

    it('the family example: its features use sessions, refresh tokens and email tokens, and no MFA', async () => {
      const failure = start(FAMILY(), storesFor(new World(), ['refreshTokens', 'emailTokens']));
      expect(named(await failure.catch((error: unknown) => error))).toEqual(['sessions']);
      moduleRef = await start(FAMILY(), storesFor(new World(), ['sessions', 'refreshTokens', 'emailTokens']));
    });

    it('a session cookie with `mfa` or `accessToken` asks for their stores too', async () => {
      const failure = (options: AuthenticationModuleOptions) =>
        start({ providers: [new Sessions()], options }, storesFor(new World(), ['sessions'])).catch((error: unknown) => error);
      expect(named(await failure({ mfa: { encryption: false } }))).toEqual(['mfa']);
      expect(named(await failure({ accessToken: { key: KEY } }))).toEqual(['refreshTokens']);
    });

    it('with nothing configured that keeps state, nothing is asked for', async () => {
      moduleRef = await start({}, storesFor(new World(), []));
    });
  });

  describe('`refreshToken: false`: access tokens alone', () => {
    const bearer = (token: string) => {
      const context = new ExecutionContextHost([{ headers: { authorization: `Bearer ${token}` } }, {}]);
      context.setType('http');
      return context;
    };

    it('starts without a RefreshTokenStore and issues access tokens the bearer provider accepts, reading no store', async () => {
      const world = new World();
      const provider = new Bearer();
      moduleRef = await start(
        { providers: [provider], options: { accessToken: { key: KEY }, refreshToken: false } },
        storesFor(world, []),
      );
      const tokens = moduleRef.get(TokenService);

      const issued = await tokens.issue('u1', { claims: { amr: ['pwd'] } });
      expect(Object.keys(issued).sort()).toEqual(['accessToken', 'expiresIn']);
      await expect(provider.authenticate(bearer(issued.accessToken))).resolves.toMatchObject({
        user: { id: 'u1' },
        session: { sub: 'u1', amr: ['pwd'] },
      });

      const disabled = 'refresh tokens are disabled (`refreshToken: false`';
      await expect(tokens.refresh('A'.repeat(43))).rejects.toThrow(disabled);
      await expect(tokens.revoke('A'.repeat(43))).rejects.toThrow(disabled);
      await expect(tokens.revokeAll('u1')).resolves.toBeUndefined();
      expect([...world.touched]).toEqual([]);
    });

    it('a session cookie app with access tokens alone needs only sessions, and signs out everywhere', async () => {
      const world = new World();
      moduleRef = await start(
        { providers: [new Sessions(), new Bearer()], options: { accessToken: { key: KEY }, refreshToken: false } },
        storesFor(world, ['sessions']),
      );
      const signIn = moduleRef.get(SignInService);

      const { token } = await signIn.signIn('u1');
      await moduleRef.get(TokenService).issue('u1');
      await signIn.signOutEverywhere('u1');
      expect(await moduleRef.get(SessionService).validate(token)).toBeNull();
      expect([...world.touched]).toEqual(['sessions']);
    });

    it('still asks a user with an authenticator for the second factor, and records it in `amr`', async () => {
      const world = new World();
      moduleRef = await start(
        { providers: [new Bearer()], options: { accessToken: { key: KEY }, refreshToken: false, mfa: { encryption: false } } },
        storesFor(world, ['mfa']),
      );
      const mfa = moduleRef.get(MfaService);
      const { secret } = await mfa.enroll('u1', 'u1@example.com');
      const step = totpStep(Math.floor(Date.now() / 1000));
      expect(await mfa.confirm('u1', hotp(base32Decode(secret), step))).toBe(true);

      const tokens = moduleRef.get(TokenService);
      await expect(tokens.issue('u1')).rejects.toMatchObject({ code: 'mfa_required' });
      const issued = await tokens.issue('u1', { secondFactor: { code: hotp(base32Decode(secret), step + 1) } });
      expect(issued).not.toHaveProperty('refreshToken');
      expect(JSON.parse(Buffer.from(issued.accessToken.split('.')[1]!, 'base64url').toString())).toMatchObject({
        sub: 'u1',
        amr: ['mfa'],
      });
      expect(world.touched.has('refreshTokens')).toBe(false);
    });

    it('warns when there are no access tokens to turn refresh tokens off for', async () => {
      const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      moduleRef = await start({ options: { refreshToken: false } }, storesFor(new World(), []));
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('`refreshToken: false` has no effect without `accessToken`'));
    });
  });

  describe('a read outside the configured features', () => {
    /** A bearer-token API, its contracts registered, that calls SessionService itself. */
    const API = (options: AuthenticationModuleOptions = {}): Setup => ({
      providers: [new Bearer()],
      options: { accessToken: { key: KEY }, ...options },
    });

    it('fails at that read in production, naming the contract, instead of running in memory', async () => {
      const world = new World();
      moduleRef = await start(API(), storesFor(world, ['refreshTokens']));

      await expect(moduleRef.get(SessionService).create('u1')).rejects.toThrow(
        'AuthenticationStorage: no store is registered for `sessions` (SessionStore), and NODE_ENV is "production": in ' +
          'memory, sessions would be lost on restart and not shared between instances. Implement SessionStore in a ' +
          'provider that injects AuthenticationStorage and calls `storage.registerSource({ sessions: this })` in its ' +
          'constructor, or set `allowInMemoryStorage: true` in the AuthenticationModule options to run in memory anyway.',
      );
      expect(() => moduleRef!.get(AuthenticationStorage).sessions).toThrow('`sessions` (SessionStore)');

      // What it registered keeps working.
      await expect(moduleRef.get(TokenService).issue('u1')).resolves.toMatchObject({ expiresIn: 900 });
    });

    it('runs in memory with allowInMemoryStorage, and outside production', async () => {
      moduleRef = await start(API({ allowInMemoryStorage: true }), storesFor(new World(), []));
      await expect(moduleRef.get(SessionService).create('u1')).resolves.toMatchObject({ session: { userId: 'u1' } });
      await moduleRef.close();

      process.env.NODE_ENV = 'development';
      moduleRef = await start(API(), storesFor(new World(), []));
      await expect(moduleRef.get(SessionService).create('u1')).resolves.toMatchObject({ session: { userId: 'u1' } });
      expect(moduleRef.get(AuthenticationStorage).sessions).toBeInstanceOf(InMemorySessionStore);
    });

    it('a registry built with `new`, outside the module, refuses in production too', () => {
      const storage = new AuthenticationStorage();
      expect(() => storage.mfa).toThrow('no store is registered for `mfa` (MfaStore)');
      const allowed = new AuthenticationStorage({ contracts: [], allowInMemoryStorage: true });
      expect(allowed.mfa).toBeInstanceOf(InMemoryMfaStore);
    });

    it('the contract suite keeps its in-memory defaults for the other contracts in production', async () => {
      const cases = authenticationStoreContract(() => new World(), { contracts: ['emailTokens'], concurrent: true });
      const services = cases.find((c) => c.name.includes('(the services)'))!;
      await services.run(); // password reset reads sessions, none registered
    });
  });
});
