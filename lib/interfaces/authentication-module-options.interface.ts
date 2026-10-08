import type { EmailVerificationOptions } from './email-verification.interface.js';
import type { PasswordResetOptions } from './password-reset.interface.js';
import type { JwtSignerOptions } from './jwt-options.interface.js';
import type { RefreshTokenOptions } from './refresh-token-options.interface.js';
import type { MagicLinkOptions } from './magic-link.interface.js';
import type { MfaOptions } from './mfa-options.interface.js';
import type { OidcOptions } from './oidc.interface.js';
import type { PasswordHasherOptions } from './password-hasher-options.interface.js';
import type { SessionOptions } from './session.interface.js';

/**
 * Configuration values: what `forRoot()` takes, and what `forRootAsync()`'s
 * factory returns. Injectable as `AUTHENTICATION_MODULE_OPTIONS`. Classes
 * are never options: credential providers and feature handlers are
 * providers of your own modules that register themselves with
 * `AuthenticationRegistry`, and stores with `AuthenticationStorage`.
 */
export interface AuthenticationModuleOptions {
  session?: SessionOptions;
  password?: PasswordHasherOptions;
  /** Enables TOTP enrollment. Requires `encryption`. */
  mfa?: MfaOptions;
  /** Goes with a registered `MagicLinkHandler` (`'magicLink'`): each fails at startup without the other. */
  magicLink?: MagicLinkOptions;
  /**
   * The access tokens `TokenService` issues, and that `JwtBearerProvider`
   * verifies unless it is given its own `key` or `jwks`.
   */
  accessToken?: JwtSignerOptions;
  /**
   * The refresh tokens `TokenService` issues with each access token, on by
   * default with `accessToken` (which then needs a `RefreshTokenStore`).
   * `false` turns them off: `issue()` returns an access token alone and
   * starts no family, `refresh()` and `revoke()` throw, `revokeAll()` does
   * nothing, and no `RefreshTokenStore` is needed. For a service that signs
   * its own short-lived access tokens, or one that only verifies them
   * (which can also leave `accessToken` out and give its
   * `JwtBearerProvider` the key: `super({ key })`). Declare
   * `refreshTokens: false` on `AuthenticationTypes` to type `issue()`
   * accordingly ({@link IssuedTokens}).
   */
  refreshToken?: RefreshTokenOptions | false;
  /** Goes with a registered `OidcAccountResolver` (`'oidc'`): each fails at startup without the other. */
  oidc?: OidcOptions;
  /** Goes with a registered `PasswordResetHandler` (`'passwordReset'`): each fails at startup without the other. */
  passwordReset?: PasswordResetOptions;
  /** Goes with a registered `EmailVerificationHandler` (`'emailVerification'`): each fails at startup without the other. */
  emailVerification?: EmailVerificationOptions;
  /**
   * Lets the app run in production while a contract it uses has no
   * registered store, on the in-memory default (one instance, state lost on
   * restart). Default `false`: startup fails, naming the contracts the
   * configured features use without a store, and so does the first read of
   * any other contract without one. Storage itself is never an option:
   * providers register it with `AuthenticationStorage.registerSource()`.
   */
  allowInMemoryStorage?: boolean;
}

/** The two switches that decide what the module registers, at the top level of `forRoot()` and `forRootAsync()`. */
export interface AuthenticationModuleExtras {
  /** Default `true`. */
  isGlobal?: boolean;
  /** Registers `AuthenticationGuard` as a global guard. Default `true`. */
  globalGuard?: boolean;
}

/** What `forRoot()` takes: the values, and the two switches. */
export type AuthenticationModuleForRootOptions = AuthenticationModuleOptions & AuthenticationModuleExtras;

/** What a `forRootAsync({ useClass })` or `useExisting` class implements. */
export interface AuthenticationOptionsFactory {
  createAuthenticationOptions(): AuthenticationModuleOptions | Promise<AuthenticationModuleOptions>;
}
