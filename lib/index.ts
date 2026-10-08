// Module
export { AuthenticationModule } from './authentication.module.js';
export type { AuthenticationModuleAsyncOptions } from './authentication.module-definition.js';
export { AUTHENTICATION_MODULE_OPTIONS } from './authentication.constants.js';

// Registration: credential providers and feature handlers are providers of your modules that register here
export { AuthenticationRegistry } from './services/index.js';

// Storage: the contracts below are interfaces your providers implement, registered here
export { AuthenticationStorage } from './storage/index.js';

// Routes and the current user
export { AuthenticationGuard } from './guards/index.js';
export { Authenticate, CurrentSession, CurrentUser, Public } from './decorators/index.js';
export { AuthenticationContext } from './context/index.js';
export { WsAuthenticator } from './services/index.js';

// Writing a credential provider
export { AuthenticationProvider } from './providers/index.js';

// API keys
export { ApiKeyProvider } from './providers/index.js';

// Errors: `AuthenticationError` is the base class of every error the package throws to apps
export {
  AuthenticationError,
  JwtError,
  MagicLinkError,
  MfaAlreadyEnrolledError,
  RefreshTokenError,
} from './errors/index.js';

// Audit events (also on `nestjs:authentication:<type>` diagnostics channels)
export {
  AuthenticationEvents,
  type AuthenticationEmailVerifiedEvent,
  type AuthenticationEvent,
  type AuthenticationMagicLinkRefusedEvent,
  type AuthenticationMfaDisabledEvent,
  type AuthenticationMfaEnabledEvent,
  type AuthenticationMfaFailedEvent,
  type AuthenticationMfaVerifiedEvent,
  type AuthenticationPasswordResetEvent,
  type AuthenticationPasswordResetRequestedEvent,
  type AuthenticationRecoveryCodesGeneratedEvent,
  type AuthenticationRefreshTokenReusedEvent,
  type AuthenticationSignInEvent,
  type AuthenticationSignOutEvent,
} from './events/index.js';

// Options, store contracts and public types
export type {
  AccessTokenResult,
  ApiKeyProviderOptions,
  ApiKeyRecord,
  ApiKeySession,
  AuthenticateOptions,
  AuthenticationErrorOptions,
  AuthenticationHandlerName,
  AuthenticationHandlers,
  AuthenticationModuleOptions,
  AuthenticationOptionsFactory,
  AuthenticationResult,
  AuthenticationStorageContract,
  AuthenticationStorageRegisterOptions,
  AuthenticationStorageSources,
  CreatedMagicLink,
  CredentialProvider,
  Duration,
  EmailTokenPurpose,
  EmailTokenRecord,
  EmailTokenStore,
  EmailVerificationLink,
  EmailVerificationOptions,
  GeneratedApiKey,
  IssuedSession,
  IssuedTokens,
  IssueTokensOptions,
  JwksClientOptions,
  JwsAlgorithm,
  JwtBearerProviderOptions,
  JwtClaims,
  JwtSignerOptions,
  JwtVerifierOptions,
  MagicLink,
  MagicLinkAccount,
  MagicLinkOptions,
  MagicLinkRecord,
  MagicLinkRequest,
  MagicLinkStore,
  MfaOptions,
  MfaState,
  MfaStore,
  OAuthTokens,
  OidcOptions,
  OidcProfile,
  OidcProviderConfig,
  OidcRedirect,
  OidcRequest,
  OidcResolveContext,
  OidcStartOptions,
  OidcStateStore,
  OidcTransaction,
  PasswordHasherOptions,
  PasswordResetAccount,
  PasswordResetLink,
  PasswordResetOptions,
  PasswordResetResult,
  RefreshTokenOptions,
  RefreshTokenRecord,
  RefreshTokenStore,
  RegisterHandlerOptions,
  RegisterProviderOptions,
  ResetPasswordOptions,
  SessionExtra,
  SessionOptions,
  SessionRecord,
  SessionStore,
  SignInOptions,
  TokenPair,
  TotpRecord,
} from './interfaces/index.js';

// Sessions
export { SessionCookieProvider } from './session/session-cookie.provider.js';
export { InMemorySessionStore } from './session/in-memory-session.store.js';
export { SessionService } from './session/session.service.js';
export { SignInService } from './session/sign-in.service.js';

// Passwords
export { PasswordHasher } from './services/index.js';

// Second factor (TOTP and recovery codes)
export { InMemoryMfaStore } from './mfa/in-memory-mfa.store.js';
export { MfaService } from './mfa/mfa.service.js';

// JWTs, access and refresh tokens
export { JwksClient } from './jwt/jwks.client.js';
export { JwtBearerProvider } from './jwt/jwt-bearer.provider.js';
export { JwtSigner } from './jwt/jwt-signer.service.js';
export { JwtVerifier } from './jwt/jwt-verifier.service.js';
export { InMemoryRefreshTokenStore } from './jwt/in-memory-refresh-token.store.js';
export { TokenService } from './jwt/token.service.js';

// Magic links
export { MagicLinkHandler } from './magic-link/magic-link.handler.js';
export { MagicLinkService } from './magic-link/magic-link.service.js';
export { InMemoryMagicLinkStore } from './magic-link/in-memory-magic-link.store.js';

// Password reset and email verification
export { InMemoryEmailTokenStore } from './account/in-memory-email-token.store.js';
export { EmailVerificationHandler } from './account/email-verification.handler.js';
export { EmailVerificationService } from './account/email-verification.service.js';
export { PasswordResetHandler } from './account/password-reset.handler.js';
export { PasswordResetService } from './account/password-reset.service.js';

// OAuth 2.0 / OpenID Connect
export { OidcAccountResolver } from './oidc/oidc-account.resolver.js';
export { OidcService } from './oidc/oidc.service.js';
export { InMemoryOidcStateStore } from './oidc/in-memory-oidc-state.store.js';
export { github, google, microsoft } from './oidc/oidc.presets.js';

/**
 * Augment once per app to type `@CurrentUser('key')`,
 * `AuthenticationContext.user` and `AuthenticationContext.session`,
 * (`sessionExtra`) what a `SessionStore` reads with each session for
 * `SessionCookieProvider.validate()` (`SessionRecord.extra`), and
 * (`refreshTokens: false`, with the `refreshToken: false` option) that
 * `TokenService.issue()` returns no refresh token ({@link IssuedTokens}):
 *
 * @example
 * declare module '@nestjs/authentication' {
 *   interface AuthenticationTypes {
 *     user: User;
 *     sessionExtra: { user: User };
 *   }
 * }
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface AuthenticationTypes {}
