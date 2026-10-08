import {
  Authenticate,
  AuthenticationContext,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  AuthenticationStorage,
  PasswordResetHandler,
  InMemoryMfaStore,
  InMemorySessionStore,
  SessionCookieProvider,
  type AuthenticationEvent,
  type AuthenticationMfaFailedEvent,
  type AuthenticationModuleOptions,
  type AuthenticationOptionsFactory,
  type MfaStore,
  type SessionExtra,
  type SessionRecord,
  type SessionStore,
} from '../lib/index.js';
import { type User } from './fixtures.js';

// Compile-time checks, verified by `tsc --noEmit`. `fixtures.ts` augments
// `AuthenticationTypes` with `user: User`.

export class Handlers {
  ok(@CurrentUser() user: User, @CurrentUser('email') email: string) {
    return [user, email];
  }

  // @ts-expect-error 'emial' is not a key of User
  typo(@CurrentUser('emial') email: string) {
    return email;
  }
}

export function contextTypes(auth: AuthenticationContext, custom: AuthenticationContext<{ tenant: string }>) {
  const user: User | null = auth.user;
  const required: User = auth.requireUser();
  const tenant: string | undefined = custom.user?.tenant;
  // @ts-expect-error the augmented user has no `tenant`
  void auth.user?.tenant;
  return [user, required, tenant];
}

// `SessionRecord.extra` is typed by `sessionExtra` on `AuthenticationTypes` (`{ user: User }` in fixtures.ts).
export function sessionExtraTypes(session: SessionRecord) {
  const extra: SessionExtra | undefined = session.extra;
  const user: User | undefined = session.extra?.user;
  // @ts-expect-error `extra` holds `{ user }`, not the user
  const notUser: User | undefined = session.extra;
  return [extra, user, notUser];
}

// Classes are never options: providers and handlers register with AuthenticationRegistry.
export const providersAreNotOptions = () =>
  AuthenticationModule.forRoot({
    // @ts-expect-error credential providers register themselves: registry.registerProvider(this)
    providers: [SessionCookieProvider],
  });
export const handlersAreNotOptions = () =>
  AuthenticationModule.forRootAsync({
    // @ts-expect-error handlers register themselves: registry.registerHandler('passwordReset', this)
    passwordResetHandler: PasswordResetHandler,
    useFactory: (): AuthenticationModuleOptions => ({}),
  });

// Values, plus the two switches, in forRoot().
export const flat = AuthenticationModule.forRoot({
  isGlobal: false,
  session: { absoluteTtl: '14d', idleTtl: 3 * 86_400_000 },
  allowInMemoryStorage: true,
});

export function registrations(registry: AuthenticationRegistry, reset: PasswordResetHandler) {
  registry.registerProvider({ authenticate: () => null }, { order: 1 });
  // @ts-expect-error a credential provider has authenticate()
  registry.registerProvider({ validate: () => null });

  registry.registerHandler('passwordReset', reset);
  // @ts-expect-error the handler of `magicLink` is a MagicLinkHandler
  registry.registerHandler('magicLink', reset);
  // @ts-expect-error features are named after their options: `passwordReset`
  registry.registerHandler('passwordResetHandler', reset);

  const handler: PasswordResetHandler | undefined = registry.handler('passwordReset');
  return handler;
}

// Storage is registered by providers, never configured (functions: at runtime, `stores` throws).
export const storesAreNotOptions = () =>
  AuthenticationModule.forRoot({
    // @ts-expect-error storage is registered with AuthenticationStorage.registerSource()
    stores: { session: InMemorySessionStore },
  });

// One class may implement several contracts (their method names never collide), and registers each by name.
export class BothStores extends InMemorySessionStore implements SessionStore, MfaStore {
  private readonly mfa = new InMemoryMfaStore();
  constructor(storage: AuthenticationStorage) {
    super();
    storage.registerSource({ sessions: this, mfa: this });
  }
  getTotp = this.mfa.getTotp.bind(this.mfa);
  saveTotp = this.mfa.saveTotp.bind(this.mfa);
  claimTotpStep = this.mfa.claimTotpStep.bind(this.mfa);
  saveRecoveryCodes = this.mfa.saveRecoveryCodes.bind(this.mfa);
  consumeRecoveryCode = this.mfa.consumeRecoveryCode.bind(this.mfa);
  countRecoveryCodes = this.mfa.countRecoveryCodes.bind(this.mfa);
  recordMfaFailure = this.mfa.recordMfaFailure.bind(this.mfa);
  countMfaFailures = this.mfa.countMfaFailures.bind(this.mfa);
  clearMfaFailures = this.mfa.clearMfaFailures.bind(this.mfa);
}
export function wrongContract(storage: AuthenticationStorage) {
  // @ts-expect-error an MFA store is not a session store
  storage.registerSource({ sessions: new InMemoryMfaStore() });
  // @ts-expect-error contracts are named: `sessions`, not `session`
  storage.registerSource({ session: new InMemorySessionStore() });
  const sessions: SessionStore = storage.sessions;
  return sessions;
}

export const badDuration = AuthenticationModule.forRoot({
  // @ts-expect-error durations are milliseconds or strings such as '3d'
  session: { idleTtl: '3 days' },
});

// forRootAsync: values from the factory.
export const asyncOk = AuthenticationModule.forRootAsync({
  useFactory: (): AuthenticationModuleOptions => ({ session: { idleTtl: '1h' } }),
});

export const asyncStoresAreNotOptions = () =>
  AuthenticationModule.forRootAsync({
    // @ts-expect-error storage is registered with AuthenticationStorage.registerSource()
    stores: { mfa: InMemoryMfaStore },
    useFactory: (): AuthenticationModuleOptions => ({ allowInMemoryStorage: true }),
  });

// forRootAsync({ useClass }): Nest's naming, as `createJwtOptions()` and `createThrottlerOptions()`.
export class AuthConfig implements AuthenticationOptionsFactory {
  createAuthenticationOptions(): AuthenticationModuleOptions {
    return { session: { idleTtl: '1h' } };
  }
}
export const withClass = AuthenticationModule.forRootAsync({ useClass: AuthConfig });
export const wrongFactoryMethod = AuthenticationModule.forRootAsync({
  // @ts-expect-error the method is createAuthenticationOptions()
  useClass: class {
    create(): AuthenticationModuleOptions {
      return {};
    }
  },
});

// Event payloads narrow on `type`.
export function locked(event: AuthenticationEvent): boolean {
  if (event.type !== 'mfa-failed') {
    return false;
  }
  const failed: AuthenticationMfaFailedEvent = event;
  return failed.locked;
}

// Encryption keys are the key material; their ids are derived from it.
export const keys: AuthenticationModuleOptions = {
  mfa: { encryption: { keys: ['k'.repeat(32), Buffer.alloc(32)] } },
};
export const namedKeys: AuthenticationModuleOptions = {
  // @ts-expect-error no user-supplied key ids
  mfa: { encryption: { keys: [{ id: '2026-09', key: 'k'.repeat(32) }] } },
};

export class Routes {
  @Authenticate({ providers: [SessionCookieProvider], mfa: true })
  cookieOnly() {}

  // @ts-expect-error providers are credential provider classes
  @Authenticate({ providers: [Handlers] })
  notAProvider() {}
}

it('compiles', () => {
  expect(true).toBe(true);
});
