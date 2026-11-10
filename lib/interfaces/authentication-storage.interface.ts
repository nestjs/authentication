import type { EmailTokenStore } from './email-token-store.interface.js';
import type { RefreshTokenStore } from './refresh-token-store.interface.js';
import type { MagicLinkStore } from './magic-link-store.interface.js';
import type { MfaStore } from './mfa-store.interface.js';
import type { OidcStateStore } from './oidc-state-store.interface.js';
import type { PasskeyStore } from './passkey-store.interface.js';
import type { SessionStore } from './session-store.interface.js';

/**
 * The storage contracts, by name: what `registerSource()` takes. One
 * provider may implement several (`{ sessions: this, refreshTokens: this }`),
 * or several providers split them (sessions in Redis, the rest in SQL).
 */
export interface AuthenticationStorageSources {
  sessions?: SessionStore;
  refreshTokens?: RefreshTokenStore;
  /** Authenticators, recovery codes and failed attempts. */
  mfa?: MfaStore;
  /** Pending magic links. */
  magicLinks?: MagicLinkStore;
  /** OAuth / OpenID Connect logins in progress. */
  oidcStates?: OidcStateStore;
  /** Passkeys and the challenges in flight. */
  passkeys?: PasskeyStore;
  /** Pending password reset and email verification links. */
  emailTokens?: EmailTokenStore;
}

export type AuthenticationStorageContract = keyof AuthenticationStorageSources;

/** `registerSource()` options. */
export interface AuthenticationStorageRegisterOptions {
  /** Replace the source of a contract that is already registered (tests, a wrapper around it). */
  replace?: boolean;
}
