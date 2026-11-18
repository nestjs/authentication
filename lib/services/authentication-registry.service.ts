import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { PROVIDER_INIT, type ProviderInit } from '../providers/authentication.provider.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import type {
  AuthenticationHandlers,
  AuthenticationHandlerName,
  RegisterProviderOptions,
  RegisterHandlerOptions,
  CredentialProvider,
} from '../interfaces/authentication-registry.interface.js';

interface HandlerSpec {
  className: string;
  methods: readonly string[];
  /** Methods a handler may leave out: when it has one, it must be a method. */
  optional?: readonly string[];
  /** What the option looks like, for the message when it's missing. */
  option: string;
}

const HANDLERS: Record<AuthenticationHandlerName, HandlerSpec> = {
  emailVerification: {
    className: 'EmailVerificationHandler',
    methods: ['send', 'markVerified'],
    option: "emailVerification: { url: 'https://app.example.com/verify-email' }",
  },
  passwordReset: {
    className: 'PasswordResetHandler',
    methods: ['findUser', 'send', 'updatePassword'],
    optional: ['hashPassword'],
    option: "passwordReset: { url: 'https://app.example.com/reset-password' }",
  },
  magicLink: {
    className: 'MagicLinkHandler',
    methods: ['send', 'resolveUser'],
    option: "magicLink: { url: 'https://app.example.com/sign-in/magic' }",
  },
  oidc: {
    className: 'OidcAccountResolver',
    methods: ['resolveUser'],
    option: "oidc: { callbackUrl: 'https://app.example.com/auth/oidc/:provider/callback', providers: { … } }",
  },
};

const HANDLER_NAMES = Object.keys(HANDLERS) as AuthenticationHandlerName[];

/** @internal Locks the registry. `AuthenticationModule.onModuleInit()` and the first read call it. */
export const LOCK_REGISTRY = Symbol('AuthenticationRegistry.lock');

type Provider = CredentialProvider<unknown, unknown>;

/**
 * Where the app's credential providers and feature handlers register, from
 * their own constructors, as stores do with `AuthenticationStorage`. They
 * are ordinary providers of the app's modules, so they inject whatever
 * those modules provide:
 *
 * ```ts
 * @Injectable()
 * export class SessionAuth extends SessionCookieProvider<User> {
 *   constructor(private readonly users: UsersRepository, registry: AuthenticationRegistry) {
 *     super();
 *     registry.registerProvider(this);
 *   }
 *   // ...
 * }
 *
 * @Injectable()
 * export class PasswordResetMailer extends PasswordResetHandler {
 *   constructor(private readonly users: UsersRepository, registry: AuthenticationRegistry) {
 *     super();
 *     registry.registerHandler('passwordReset', this);
 *   }
 *   // ...
 * }
 * ```
 *
 * The registry locks in `AuthenticationModule`'s `onModuleInit` (every
 * provider constructor has run by then), or at the first read if that is
 * earlier. At the lock it fails when a feature has its option without its
 * handler, or the reverse, and it logs the chain and the handlers.
 */
@Injectable()
export class AuthenticationRegistry {
  private static readonly logger = new Logger('AuthenticationModule');
  private readonly registered: { provider: Provider; order: number }[] = [];
  private readonly handlers = new Map<AuthenticationHandlerName, object>();
  private chain: readonly Provider[] = [];
  private locked = false;

  constructor(
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) private readonly options?: Record<string, unknown>,
    @Optional() private readonly moduleRef?: ModuleRef,
  ) {}

  /**
   * Adds a credential provider to the chain the guard runs, in ascending
   * `order` (default `0`). Call it from the constructor of a singleton
   * provider. Throws, registering nothing, for an object without
   * `authenticate()`, an order another provider has (unless `replace` is
   * set), a provider registered twice, and once the registry has locked.
   */
  registerProvider(provider: CredentialProvider, { order = 0, replace = false }: RegisterProviderOptions = {}): void {
    const where = 'AuthenticationRegistry.registerProvider()';
    if (provider === null || typeof provider !== 'object' || typeof (provider as Provider).authenticate !== 'function') {
      throw new TypeError(`${where}: expected a credential provider with an authenticate() method, got ${nameOf(provider)}.`);
    }
    if (typeof order !== 'number' || !Number.isFinite(order)) {
      throw new TypeError(`${where}: \`order\` must be a finite number, got ${String(order)}.`);
    }

    this.assertOpen(where, nameOf(provider));
    if (this.registered.some((entry) => entry.provider === provider)) {
      throw new Error(`${where}: ${nameOf(provider)} is already registered (the same instance, twice).`);
    }

    const taken = this.registered.find((entry) => entry.order === order);
    if (taken && !replace) {
      if (taken.provider.constructor === provider.constructor && provider.constructor !== Object) {
        throw new Error(
          `${where}: another ${nameOf(provider)} is already registered at order ${order}. Is the class provided in ` +
            'two modules? Provide it once, in the module that owns it.',
        );
      }
      throw new Error(
        `${where}: ${nameOf(provider)} can't take order ${order}, ${nameOf(taken.provider)} has it. Providers run in ` +
          'ascending `order` and the first that returns a user wins, so each needs its own: ' +
          `\`registerProvider(this, { order: ${Math.max(...this.registered.map((entry) => entry.order)) + 1} })\`.`,
      );
    }

    if (taken) {
      this.registered.splice(this.registered.indexOf(taken), 1);
    }
    this.registered.push({ provider: provider as Provider, order });
  }

  /**
   * Registers the handler of a feature: `registerHandler('passwordReset', this)`.
   * The feature also needs its module option. Throws, registering nothing,
   * for an unknown feature, a handler missing one of its methods (or with an
   * optional one, like `hashPassword`, that isn't a method), a feature
   * that already has one (unless `replace` is set), and once the registry
   * has locked.
   */
  registerHandler<K extends AuthenticationHandlerName>(
    feature: K,
    handler: AuthenticationHandlers[K],
    { replace = false }: RegisterHandlerOptions = {},
  ): void {
    const where = 'AuthenticationRegistry.registerHandler()';
    if (!Object.hasOwn(HANDLERS, feature)) {
      throw new TypeError(
        `${where}: unknown feature \`${String(feature)}\`. The features are ` +
          `${HANDLER_NAMES.map((name) => `${name} (${HANDLERS[name].className})`).join(', ')}.`,
      );
    }

    const { className, methods, optional = [] } = HANDLERS[feature];
    if (handler === null || typeof handler !== 'object') {
      throw new TypeError(`${where}: expected a ${className} as \`${feature}\`, got ${nameOf(handler)}.`);
    }
    const missing = methods.filter((method) => typeof (handler as unknown as Record<string, unknown>)[method] !== 'function');
    if (missing.length > 0) {
      throw new TypeError(
        `${where}: ${nameOf(handler)} doesn't implement ${className} for \`${feature}\`: ` +
          `${missing.map((method) => `${method}()`).join(', ')} ${missing.length === 1 ? 'is' : 'are'} missing.`,
      );
    }
    // An optional method set to anything else would otherwise be skipped without a word.
    const notMethods = optional.filter((method) => {
      const value = (handler as unknown as Record<string, unknown>)[method];
      return value !== undefined && typeof value !== 'function';
    });
    if (notMethods.length > 0) {
      throw new TypeError(
        `${where}: ${nameOf(handler)} doesn't implement ${className} for \`${feature}\`: ` +
          `${notMethods.map((method) => `\`${method}\``).join(', ')} ${notMethods.length === 1 ? 'is' : 'are'} set, but not a method.`,
      );
    }

    this.assertOpen(where, nameOf(handler));
    const previous = this.handlers.get(feature);
    if (previous && !replace) {
      throw new Error(
        `${where}: ${nameOf(handler)} can't register \`${feature}\`, ` +
          `${previous === handler ? 'it already did (the same instance, twice)' : `${nameOf(previous)} already did`}. ` +
          'Register each feature once, or pass { replace: true } to replace it on purpose (tests, wrappers).',
      );
    }

    this.handlers.set(feature, handler);
  }

  /** The credential providers, in the order the guard runs them. Reading them locks the registry. */
  get providers(): readonly CredentialProvider<unknown, unknown>[] {
    this[LOCK_REGISTRY]();
    return this.chain;
  }

  /** The handler registered for a feature, or `undefined`. Reading it locks the registry. */
  handler<K extends AuthenticationHandlerName>(feature: K): AuthenticationHandlers[K] | undefined {
    this[LOCK_REGISTRY]();
    return this.handlers.get(feature) as AuthenticationHandlers[K] | undefined;
  }

  /**
   * @internal Checks every feature has both its option and its handler,
   * orders the chain, lets the providers check their configuration, and
   * logs what registered. `log: false` for registries built outside a
   * module (tests, the contract suite).
   */
  [LOCK_REGISTRY]({ log = true }: { log?: boolean } = {}): void {
    if (this.locked) {
      return;
    }

    const options = this.options ?? {};
    for (const feature of HANDLER_NAMES) {
      const { className, option } = HANDLERS[feature];
      const handler = this.handlers.get(feature);
      if (options[feature] !== undefined && !handler) {
        throw new Error(
          `AuthenticationModule: \`${feature}\` is configured, but no ${className} is registered. Write an ` +
            `@Injectable() class that extends ${className}, provide it in one of your modules, and register it from ` +
            `its constructor: \`registry.registerHandler('${feature}', this)\`, with \`registry: AuthenticationRegistry\` injected.`,
        );
      }
      if (handler && options[feature] === undefined) {
        throw new Error(
          `AuthenticationModule: ${nameOf(handler)} is registered as the \`${feature}\` handler, but the \`${feature}\` ` +
            `option is missing. Configure it in the AuthenticationModule options: \`${option}\`.`,
        );
      }
    }

    const chain = [...this.registered].sort((a, b) => a.order - b.order).map((entry) => entry.provider);

    // Providers that read module options check them now, not at the first request.
    const resolve = (token: any) => {
      if (!this.moduleRef) {
        throw new Error(`AuthenticationRegistry: no module to resolve ${String(token?.name ?? token)} from`);
      }
      return this.moduleRef.get(token, { strict: false });
    };
    for (const provider of chain) {
      (provider as { [PROVIDER_INIT]?: ProviderInit })[PROVIDER_INIT]?.(resolve);
    }

    this.chain = Object.freeze(chain);
    this.locked = true;
    if (!log) {
      return;
    }

    const logger = AuthenticationRegistry.logger;
    const handlers = HANDLER_NAMES.filter((feature) => this.handlers.has(feature)).map(
      (feature) => `${nameOf(this.handlers.get(feature))} (${feature})`,
    );

    if (chain.length === 0) {
      logger.warn(
        'AuthenticationRegistry: no credential provider is registered, so every route that is not @Public() answers ' +
          '401. Register one from its constructor: `registry.registerProvider(this)`.',
      );
    }

    logger.log(
      `AuthenticationRegistry: ${chain.length > 0 ? `providers ${chain.map(nameOf).join(', ')}` : 'no providers'}` +
        (handlers.length > 0 ? `; handlers ${handlers.join(', ')}` : ''),
    );
  }

  private assertOpen(where: string, name: string) {
    if (!this.locked) {
      return;
    }
    throw new Error(
      `${where}: ${name} registered after AuthenticationModule initialized (or after the registry was first read). ` +
        'Register from the constructor of a singleton provider: providers of lazy-loaded modules, request-scoped and ' +
        'transient providers, and lifecycle hooks run too late.',
    );
  }
}

/** How a message names a value: its class, or what it is instead of an instance. */
function nameOf(value: unknown): string {
  if (typeof value === 'function') {
    return `the class ${value.name || '(anonymous)'} (pass an instance: \`this\`)`;
  }
  if (value === null || typeof value !== 'object') {
    return String(value);
  }
  const name = (value as object).constructor?.name;
  return name && name !== 'Object' ? name : 'an object';
}
