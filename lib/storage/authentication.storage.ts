import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { InMemoryEmailTokenStore } from '../account/in-memory-email-token.store.js';
import type { EmailTokenStore } from '../interfaces/email-token-store.interface.js';
import { InMemoryRefreshTokenStore } from '../jwt/in-memory-refresh-token.store.js';
import type { RefreshTokenStore } from '../interfaces/refresh-token-store.interface.js';
import { InMemoryMagicLinkStore } from '../magic-link/in-memory-magic-link.store.js';
import type { MagicLinkStore } from '../interfaces/magic-link-store.interface.js';
import { InMemoryMfaStore } from '../mfa/in-memory-mfa.store.js';
import type { MfaStore } from '../interfaces/mfa-store.interface.js';
import { InMemoryOidcStateStore } from '../oidc/in-memory-oidc-state.store.js';
import type { OidcStateStore } from '../interfaces/oidc-state-store.interface.js';
import { InMemorySessionStore } from '../session/in-memory-session.store.js';
import type { SessionStore } from '../interfaces/session-store.interface.js';
import { AUTHENTICATION_STORAGE_REQUIREMENTS } from '../authentication.constants.js';
import type {
  AuthenticationStorageSources,
  AuthenticationStorageContract,
  AuthenticationStorageRegisterOptions,
} from '../interfaces/authentication-storage.interface.js';

/**
 * @internal What each feature reads or writes, audited against the code
 * paths: the production guard's rule.
 * MFA is off unless `mfa` is configured: without it, `MfaService.isEnrolled()`
 * answers `false` without reading the store, and its other methods throw.
 * Refresh tokens exist only with `accessToken`, and not with
 * `refreshToken: false`: otherwise `TokenService.issue()` starts no family
 * and `revokeAll()` has nothing to revoke and reads nothing. Apps
 * that sign users in from a shared user database must therefore agree: if
 * one configures `mfa` (or `accessToken`), every one of them must, or a user
 * who enrolled an authenticator through one signs in to another with a
 * password alone (and a sign-out everywhere leaves token clients signed in).
 * Removing `mfa` turns MFA off for everyone.
 */
export const CONTRACTS_BY_FEATURE = {
  /**
   * A `SessionCookieProvider` in `providers`: `SessionService` (every
   * request), `SignInService.signIn()` and `signOutEverywhere()`.
   */
  sessionCookie: ['sessions'],
  /**
   * `accessToken` without `refreshToken: false`: the refresh-token families
   * `TokenService` starts, which every sign-out everywhere revokes too.
   * Access tokens alone keep no state.
   */
  refreshToken: ['refreshTokens'],
  /** `mfa`: enrollment, codes, recovery codes and the lockout; every sign-in checks for an authenticator. */
  mfa: ['mfa'],
  /** `magicLinkHandler`: pending links, then `SignInService.signIn()`. */
  magicLink: ['sessions', 'magicLinks'],
  /** `oidcAccountResolver`: logins in progress, the session that links an account, then `SignInService.signIn()`. */
  oidc: ['sessions', 'oidcStates'],
  /**
   * `passwordResetHandler`: the links; `reset()` revokes every session (and
   * refresh-token family, with refresh tokens on) of the user, and with
   * `signIn: true` signs in.
   */
  passwordReset: ['sessions', 'emailTokens'],
  /** `emailVerificationHandler`: the links. */
  emailVerification: ['emailTokens'],
} as const satisfies Record<string, readonly AuthenticationStorageContract[]>;

/** @internal */
export type AuthenticationFeature = keyof typeof CONTRACTS_BY_FEATURE;

/** @internal The contracts the features use, in the order messages list them. */
export function contractsUsedBy(features: Iterable<AuthenticationFeature>): AuthenticationStorageContract[] {
  const used = new Set<AuthenticationStorageContract>();
  for (const feature of features) {
    for (const contract of CONTRACTS_BY_FEATURE[feature]) {
      used.add(contract);
    }
  }
  return CONTRACT_NAMES.filter((contract) => used.has(contract));
}

/** @internal What the configured features need from storage, computed by the module from its options. */
export interface AuthenticationStorageRequirements {
  /** The contracts a configured feature uses ({@link contractsUsedBy}): the production guard checks these at startup. */
  contracts: AuthenticationStorageContract[];
  allowInMemoryStorage: boolean;
}

interface ContractSpec {
  interfaceName: string;
  /** What is lost with the in-memory default, for the production guard. */
  holds: string;
  methods: readonly string[];
  inMemory: () => object;
}

/** @internal Every contract, in the order they are listed in messages. */
export const STORAGE_CONTRACTS: Record<AuthenticationStorageContract, ContractSpec> = {
  sessions: {
    interfaceName: 'SessionStore',
    holds: 'sessions',
    methods: ['getSession', 'createSession', 'touchSession', 'deleteSession', 'listUserSessions', 'deleteUserSessions'],
    inMemory: () => new InMemorySessionStore(),
  },
  refreshTokens: {
    interfaceName: 'RefreshTokenStore',
    holds: 'refresh tokens',
    methods: [
      'getRefreshToken',
      'saveRefreshToken',
      'markRefreshTokenUsed',
      'revokeRefreshTokenFamily',
      'isRefreshTokenFamilyRevoked',
      'revokeUserRefreshTokens',
    ],
    inMemory: () => new InMemoryRefreshTokenStore(),
  },
  mfa: {
    interfaceName: 'MfaStore',
    holds: 'authenticators and recovery codes',
    methods: [
      'getTotp',
      'saveTotp',
      'claimTotpStep',
      'saveRecoveryCodes',
      'consumeRecoveryCode',
      'countRecoveryCodes',
      'recordMfaFailure',
      'countMfaFailures',
      'clearMfaFailures',
    ],
    inMemory: () => new InMemoryMfaStore(),
  },
  magicLinks: {
    interfaceName: 'MagicLinkStore',
    holds: 'pending magic links',
    methods: ['saveMagicLink', 'consumeMagicLink'],
    inMemory: () => new InMemoryMagicLinkStore(),
  },
  oidcStates: {
    interfaceName: 'OidcStateStore',
    holds: 'OIDC logins in progress',
    methods: ['saveOidcState', 'consumeOidcState'],
    inMemory: () => new InMemoryOidcStateStore(),
  },
  emailTokens: {
    interfaceName: 'EmailTokenStore',
    holds: 'password reset and verification links',
    methods: ['saveEmailToken', 'consumeEmailToken', 'deleteUserEmailTokens'],
    inMemory: () => new InMemoryEmailTokenStore(),
  },
};

const CONTRACT_NAMES = Object.keys(STORAGE_CONTRACTS) as AuthenticationStorageContract[];
const KNOWN = CONTRACT_NAMES.map((name) => `${name} (${STORAGE_CONTRACTS[name].interfaceName})`).join(', ');
const DEFAULT = 'in-memory stores (the default: state is lost on restart and not shared between instances)';

/** @internal Locks the registry. `AuthenticationModule.onModuleInit()` and the first read call it. */
export const LOCK_STORAGE = Symbol('AuthenticationStorage.lock');

/**
 * Where the module keeps its state. The app registers its own stores here,
 * from the constructor of an ordinary provider:
 *
 * ```ts
 * @Injectable()
 * export class DrizzleAuthenticationStore implements SessionStore, RefreshTokenStore, MfaStore {
 *   constructor(@Inject(DRIZZLE) private readonly db: Database, storage: AuthenticationStorage) {
 *     storage.registerSource({ sessions: this, refreshTokens: this, mfa: this });
 *   }
 *   // ...
 * }
 * ```
 *
 * A contract no source registered uses the in-memory store, so an app that
 * imports the module boots with no storage configured. The registry locks
 * in `AuthenticationModule`'s `onModuleInit` (every provider constructor has
 * run by then), or at the first read of a store if that is earlier (another
 * module's `onModuleInit`): it logs the active sources, and in production
 * refuses to start while a contract a configured feature uses has no
 * source, unless `allowInMemoryStorage` is set. In production, a read of
 * any other contract without a source (an app calling a service outside
 * the features it configured) fails the same way at that read, instead of
 * running on the in-memory default.
 */
@Injectable()
export class AuthenticationStorage {
  private static readonly logger = new Logger('AuthenticationModule');
  private readonly registered = new Map<AuthenticationStorageContract, object>();
  private readonly active = new Map<AuthenticationStorageContract, object>();
  private locked = false;

  constructor(
    @Optional()
    @Inject(AUTHENTICATION_STORAGE_REQUIREMENTS)
    private readonly requirements?: AuthenticationStorageRequirements,
  ) {}

  /**
   * Registers stores by contract: `{ sessions: this, refreshTokens: this }`.
   * Call it from the constructor of a singleton provider. Throws, registering
   * nothing, when a store lacks one of its contract's methods, when a
   * contract already has a source (unless `replace` is set: tests,
   * wrappers), and once the registry has locked.
   */
  registerSource(sources: AuthenticationStorageSources, options: AuthenticationStorageRegisterOptions = {}): void {
    const entries = validate(sources);
    if (this.locked) {
      throw new Error(
        `AuthenticationStorage.registerSource(): ${describe(entries)} registered after AuthenticationModule initialized ` +
          `(or after its storage was first read), which already uses ${this.summary(CONTRACT_NAMES)}. Register from ` +
          'the constructor of a singleton provider: providers of lazy-loaded modules, request-scoped and transient ' +
          'providers, and lifecycle hooks run too late.',
      );
    }

    if (!options.replace) {
      for (const [contract, source] of entries) {
        const previous = this.registered.get(contract);
        if (previous) {
          throw new Error(
            `AuthenticationStorage.registerSource(): ${nameOf(source)} can't register \`${contract}\`, ` +
              `${previous === source ? 'it already did (the same instance, twice)' : `${nameOf(previous)} already did`}. ` +
              'Register each contract once, or pass { replace: true } to replace it on purpose (tests, wrappers).',
          );
        }
      }
    }

    for (const [contract, source] of entries) {
      this.registered.set(contract, source);
    }
  }

  /** The active session store: the registered one, else the in-memory default. Reading it locks the registry. */
  get sessions(): SessionStore {
    return this.source('sessions') as SessionStore;
  }
  get refreshTokens(): RefreshTokenStore {
    return this.source('refreshTokens') as RefreshTokenStore;
  }
  get mfa(): MfaStore {
    return this.source('mfa') as MfaStore;
  }
  get magicLinks(): MagicLinkStore {
    return this.source('magicLinks') as MagicLinkStore;
  }
  get oidcStates(): OidcStateStore {
    return this.source('oidcStates') as OidcStateStore;
  }
  get emailTokens(): EmailTokenStore {
    return this.source('emailTokens') as EmailTokenStore;
  }

  /**
   * @internal Freezes the sources, logs them, and enforces the production
   * guard (which leaves the registry open): in production, a contract in use
   * with no source fails unless in-memory storage was allowed. `log: false`
   * for the contract suite, which builds a registry per case.
   */
  [LOCK_STORAGE]({ log = true }: { log?: boolean } = {}): void {
    if (this.locked) {
      return;
    }

    const inUse = this.requirements?.contracts ?? [];
    const missing = inUse.filter((contract) => !this.registered.has(contract));
    if (missing.length > 0 && this.refusesInMemory()) {
      throw new Error(productionError(missing));
    }

    this.locked = true;
    for (const [contract, source] of this.registered) {
      this.active.set(contract, source);
    }

    if (log) {
      AuthenticationStorage.logger.log(`AuthenticationStorage: ${this.summary(inUse)}`);
    }
  }

  private source(contract: AuthenticationStorageContract): object {
    this[LOCK_STORAGE]();

    let source = this.active.get(contract);
    if (!source) {
      // A contract no configured feature showed as used: never in memory in production either.
      if (this.refusesInMemory()) {
        throw new Error(productionError([contract]));
      }
      source = STORAGE_CONTRACTS[contract].inMemory();
      this.active.set(contract, source);
    }
    return source;
  }

  /**
   * In production, unless `allowInMemoryStorage` is set. A registry built
   * with `new`, outside the module, has no options: it refuses too.
   */
  private refusesInMemory(): boolean {
    // `Production` and `production ` (a stray space in a .env file) are production too.
    return process.env.NODE_ENV?.trim().toLowerCase() === 'production' && !this.requirements?.allowInMemoryStorage;
  }

  /**
   * The in-memory default, `DrizzleAuthenticationStore` (one source for every
   * contract), or the contracts in use or registered, by source:
   * `RedisSessionStore (sessions); DrizzleAuthenticationStore (mfa); in-memory (oidcStates)`.
   */
  private summary(inUse: AuthenticationStorageContract[]): string {
    const sources = new Set(this.registered.values());
    if (sources.size === 0) {
      return DEFAULT;
    }
    if (sources.size === 1 && this.registered.size === CONTRACT_NAMES.length) {
      return nameOf([...sources][0]);
    }

    const listed = CONTRACT_NAMES.filter((contract) => inUse.includes(contract) || this.registered.has(contract));
    const groups = new Map<string, string[]>();
    // The registered sources first, then what runs in memory.
    for (const contract of [...listed.filter((c) => this.registered.has(c)), ...listed.filter((c) => !this.registered.has(c))]) {
      const source = this.registered.get(contract);
      const name = source ? nameOf(source) : 'in-memory';
      groups.set(name, [...(groups.get(name) ?? []), contract]);
    }

    return [...groups].map(([name, contracts]) => `${name} (${contracts.join(', ')})`).join('; ');
  }
}

/** The `[contract, store]` pairs of a `registerSource()` argument, after checking every one. */
function validate(sources: AuthenticationStorageSources): [AuthenticationStorageContract, object][] {
  if (sources === null || typeof sources !== 'object') {
    throw new TypeError(`AuthenticationStorage.registerSource(): the contracts go by name, and got ${nameOf(sources)}. ${usage()}`);
  }

  // A store passed as itself (`registerSource(this)`): say which call it meant.
  const implemented = CONTRACT_NAMES.filter((contract) =>
    STORAGE_CONTRACTS[contract].methods.some((method) => typeof (sources as Record<string, unknown>)[method] === 'function'),
  );
  if (implemented.length > 0) {
    throw new TypeError(
      `AuthenticationStorage.registerSource(): the contracts go by name, and ${nameOf(sources)} was passed as itself. ` +
        `Name what it implements: \`registerSource({ ${implemented.map((contract) => `${contract}: this`).join(', ')} })\`.`,
    );
  }

  const keys = Object.keys(sources);
  if (keys.length === 0) {
    throw new TypeError(`AuthenticationStorage.registerSource(): the contracts go by name, and got none. ${usage()}`);
  }

  const unknown = keys.filter((key) => !Object.hasOwn(STORAGE_CONTRACTS, key));
  if (unknown.length > 0) {
    throw new TypeError(
      `AuthenticationStorage.registerSource(): unknown contract ${unknown.map((key) => `\`${key}\``).join(', ')}. ` +
        `The contracts are ${KNOWN}.`,
    );
  }

  return (keys as AuthenticationStorageContract[]).map((contract) => {
    const source = sources[contract] as unknown;
    const { interfaceName, methods } = STORAGE_CONTRACTS[contract];

    if (source === null || typeof source !== 'object') {
      throw new TypeError(
        `AuthenticationStorage.registerSource(): expected an object implementing ${interfaceName} as \`${contract}\`, ` +
          `got ${nameOf(source)}.`,
      );
    }

    const missing = methods.filter((method) => typeof (source as Record<string, unknown>)[method] !== 'function');
    if (missing.length > 0) {
      throw new TypeError(
        `AuthenticationStorage.registerSource(): ${nameOf(source)} doesn't implement ${interfaceName} for \`${contract}\`: ` +
          `${missing.map((method) => `${method}()`).join(', ')} ${missing.length === 1 ? 'is' : 'are'} missing.`,
      );
    }

    return [contract, source];
  });
}

function usage(): string {
  return `Pass the stores a provider implements: \`registerSource({ sessions: this, refreshTokens: this })\`. The contracts are ${KNOWN}.`;
}

function productionError(missing: AuthenticationStorageContract[]): string {
  const specs = missing.map((contract) => STORAGE_CONTRACTS[contract]);
  const example = missing.map((contract) => `${contract}: this`).join(', ');
  return (
    `AuthenticationStorage: no store is registered for ${and(missing.map((contract, i) => `\`${contract}\` (${specs[i]!.interfaceName})`))}, ` +
    `and NODE_ENV is "production": in memory, ${and(specs.map((spec) => spec.holds))} would be lost on restart and not ` +
    `shared between instances. Implement ${and(specs.map((spec) => spec.interfaceName))} in a provider that injects ` +
    `AuthenticationStorage and calls \`storage.registerSource({ ${example} })\` in its constructor, or set ` +
    '`allowInMemoryStorage: true` in the AuthenticationModule options to run in memory anyway.'
  );
}

/** `a`, `a and b`, `a, b, and c`. */
function and(items: string[]): string {
  if (items.length <= 2) {
    return items.join(' and ');
  }
  return `${items.slice(0, -1).join(', ')}, and ${items.at(-1)}`;
}

/** How a message names a value: its class, or what it is instead of an instance. */
function nameOf(value: unknown): string {
  if (typeof value === 'function') {
    return `the class ${value.name || '(anonymous)'} (pass an instance)`;
  }
  if (value === null || typeof value !== 'object') {
    return String(value);
  }
  const name = (value as object).constructor?.name;
  return name && name !== 'Object' ? name : 'an object';
}

/** `DrizzleAuthenticationStore (sessions, mfa)`: the sources of a `registerSource()` call. */
function describe(entries: [AuthenticationStorageContract, object][]): string {
  const names = [...new Set(entries.map(([, source]) => nameOf(source)))].join(', ');
  return `${names} (${entries.map(([contract]) => contract).join(', ')})`;
}
