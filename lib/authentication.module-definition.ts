import { ConfigurableModuleBuilder, Logger, type Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthenticationGuard } from './guards/authentication.guard.js';
import { AuthenticationRegistry, LOCK_REGISTRY } from './services/authentication-registry.service.js';
import {
  contractsUsedBy,
  type AuthenticationFeature,
  type AuthenticationStorageRequirements,
} from './storage/authentication.storage.js';
import { AUTHENTICATION_MODULE_OPTIONS, AUTHENTICATION_STORAGE_REQUIREMENTS } from './authentication.constants.js';
import type { Duration } from './interfaces/duration.interface.js';
import { SessionCookieProvider } from './session/session-cookie.provider.js';
import type {
  AuthenticationModuleOptions,
  AuthenticationModuleExtras,
} from './interfaces/authentication-module-options.interface.js';

export const { ConfigurableModuleClass, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } =
  new ConfigurableModuleBuilder<AuthenticationModuleOptions>({ optionsInjectionToken: AUTHENTICATION_MODULE_OPTIONS })
    .setClassMethodName('forRoot')
    .setFactoryMethodName('createAuthenticationOptions')
    .setExtras<AuthenticationModuleExtras>({ isGlobal: true, globalGuard: true }, (definition, extras) => ({
      ...definition,
      global: extras.isGlobal ?? true,
      providers: [
        ...(definition.providers ?? []),
        ...(extras.globalGuard === false ? [] : [{ provide: APP_GUARD, useExisting: AuthenticationGuard }]),
      ],
    }))
    .build();

/** What `forRootAsync()` takes: `useFactory`, `useClass` or `useExisting`, with `imports` and `inject` for them. */
export type AuthenticationModuleAsyncOptions = typeof ASYNC_OPTIONS_TYPE;

/** @internal The module options, once `startupChecks()` accepted them. */
export const CHECKED_OPTIONS = Symbol('AUTHENTICATION_CHECKED_OPTIONS');

/**
 * @internal Runs once at startup: fails on options that don't exist (the
 * classes that used to be options among them), then warns about lifetimes
 * that look like seconds.
 */
export const startupChecks: Provider = {
  provide: CHECKED_OPTIONS,
  inject: [AUTHENTICATION_MODULE_OPTIONS],
  useFactory: (resolved: AuthenticationModuleOptions | undefined) => {
    const options = resolved ?? {};
    checkKeys(options);
    const logger = new Logger('AuthenticationModule');
    warnShortLifetimes(options, logger);
    warnIdleSwitches(options, logger);
    return options;
  },
};

/**
 * @internal The storage contracts the configured features use, for the
 * production guard: the features the options and the registered providers
 * enable, and what each one reads or writes (`CONTRACTS_BY_FEATURE`, the one
 * place that says so). Computed when storage locks, which locks the
 * registry first: the credential providers decide whether sessions are used.
 */
export const storageRequirements: Provider = {
  provide: AUTHENTICATION_STORAGE_REQUIREMENTS,
  inject: [CHECKED_OPTIONS, AuthenticationRegistry],
  useFactory: (options: AuthenticationModuleOptions, registry: AuthenticationRegistry): AuthenticationStorageRequirements => ({
    get contracts() {
      registry[LOCK_REGISTRY]();

      const enabled: Record<AuthenticationFeature, boolean> = {
        sessionCookie: registry.providers.some((provider) => provider instanceof SessionCookieProvider),
        // With `accessToken`, unless turned off: they are what `issue()` stores.
        refreshToken: options.accessToken !== undefined && options.refreshToken !== false,
        mfa: options.mfa !== undefined,
        // With their handlers: the registry refuses one without the other.
        magicLink: options.magicLink !== undefined,
        oidc: options.oidc !== undefined,
        passwordReset: options.passwordReset !== undefined,
        emailVerification: options.emailVerification !== undefined,
      };

      return contractsUsedBy((Object.keys(enabled) as AuthenticationFeature[]).filter((feature) => enabled[feature]));
    },
    allowInMemoryStorage: options.allowInMemoryStorage === true,
  }),
};

const KNOWN_OPTIONS = new Set<string>([
  'session',
  'password',
  'mfa',
  'magicLink',
  'accessToken',
  'refreshToken',
  'oidc',
  'passwordReset',
  'emailVerification',
  'allowInMemoryStorage',
] satisfies (keyof AuthenticationModuleOptions)[]);

/** Where each class that used to be an option registers now. */
const REGISTERED: Record<string, string> = {
  providers:
    'credential providers register themselves: provide the class in one of your modules, and call ' +
    '`registry.registerProvider(this, { order })` from its constructor, with `registry: AuthenticationRegistry` injected',
  magicLinkHandler: "handlers register themselves: `registry.registerHandler('magicLink', this)` from the handler's constructor",
  oidcAccountResolver: "handlers register themselves: `registry.registerHandler('oidc', this)` from the resolver's constructor",
  passwordResetHandler: "handlers register themselves: `registry.registerHandler('passwordReset', this)` from the handler's constructor",
  emailVerificationHandler:
    "handlers register themselves: `registry.registerHandler('emailVerification', this)` from the handler's constructor",
  oidcPath: 'the OIDC routes are your own controller now, calling OidcService; set `oidc.callbackUrl` to its callback URL',
  imports: 'forRoot() takes values only; forRootAsync() takes `imports` for its factory',
  stores:
    'storage is registered by a provider: implement the store interfaces in an @Injectable() class and call ' +
    '`storage.registerSource({ sessions: this, … })` from its constructor, with `storage: AuthenticationStorage` injected',
};

/**
 * An option that doesn't exist fails at startup instead of being ignored: a
 * class where registration belongs, a switch returned by a `forRootAsync()`
 * factory (it goes at the top level, next to `useFactory`), or a typo.
 */
function checkKeys(options: AuthenticationModuleOptions) {
  for (const key of Object.keys(options)) {
    if (KNOWN_OPTIONS.has(key)) {
      continue;
    }

    if (key === 'isGlobal' || key === 'globalGuard') {
      throw new Error(
        `AuthenticationModule: \`${key}\` is in the options the factory returned. It goes at the top level of ` +
          'forRootAsync(), next to useFactory, because it decides what the module registers.',
      );
    }

    const hint = REGISTERED[key];
    throw new Error(
      `AuthenticationModule: \`${key}\` is not an option` +
        (hint ? `: ${hint}.` : `. The options are ${[...KNOWN_OPTIONS].join(', ')}.`),
    );
  }
}

/** A switch that turns off what isn't on: harmless, and likely a forgotten option. */
function warnIdleSwitches(options: AuthenticationModuleOptions, logger: Logger) {
  if (options.refreshToken === false && options.accessToken === undefined) {
    logger.warn(
      '`refreshToken: false` has no effect without `accessToken`: refresh tokens are only issued with access tokens.',
    );
  }
}

/** The lifetimes: what `@nestjs/jwt` and jsonwebtoken users are used to giving in seconds. */
const LIFETIMES: [path: string, read: (options: AuthenticationModuleOptions) => Duration | undefined][] = [
  ['accessToken.ttl', (options) => options.accessToken?.ttl],
  ['refreshToken.ttl', (options) => (options.refreshToken || undefined)?.ttl],
  ['refreshToken.absoluteTtl', (options) => (options.refreshToken || undefined)?.absoluteTtl],
  ['session.absoluteTtl', (options) => options.session?.absoluteTtl],
  ['session.idleTtl', (options) => options.session?.idleTtl],
  ['mfa.pendingTtl', (options) => options.mfa?.pendingTtl],
  ['magicLink.ttl', (options) => options.magicLink?.ttl],
  ['oidc.transactionTtl', (options) => options.oidc?.transactionTtl],
  ['passwordReset.ttl', (options) => options.passwordReset?.ttl],
  ['emailVerification.ttl', (options) => options.emailVerification?.ttl],
];

/**
 * A numeric lifetime is milliseconds, so `ttl: 3600` means 3.6 seconds,
 * not the hour a `@nestjs/jwt` user meant. One warning per lifetime under a
 * minute (`0`, which turns `session.idleTtl` off, excepted), suggesting the
 * string that the number would mean in seconds.
 */
function warnShortLifetimes(options: AuthenticationModuleOptions, logger: Logger) {
  for (const [path, read] of LIFETIMES) {
    const value = read(options);
    if (typeof value !== 'number' || !(value > 0 && value < 60_000)) {
      continue;
    }

    logger.warn(
      `\`${path}\` is ${value} milliseconds. Numeric lifetimes are milliseconds, not seconds as in ` +
        `@nestjs/jwt: did you mean '${asSeconds(value)}'?`,
    );
  }
}

/** `value` read as seconds, in the largest whole unit: 900 is `15m`, 3600 is `1h`. */
function asSeconds(value: number): string {
  if (value % 3_600 === 0) {
    return `${value / 3_600}h`;
  }
  if (value % 60 === 0) {
    return `${value / 60}m`;
  }
  return `${value}s`;
}
