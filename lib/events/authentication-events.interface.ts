import type { MfaState } from '../interfaces/authentication-result.interface.js';

/**
 * A first factor signed a user in: a cookie session (`SignInService`), or a
 * refresh-token family for a token client (`TokenService.issue()`).
 */
export interface AuthenticationSignInEvent {
  type: 'sign-in';
  userId: string;
  /** The new cookie session. */
  sessionId?: string;
  /** The new refresh-token family. */
  tokenFamilyId?: string;
  /** How the user proved who they are, when the caller said: `password`, `magic-link`, `oidc:google`. */
  method?: string;
  /**
   * `pending` while the session still needs its second factor; `verified`
   * for tokens issued with one (`TokenService.issue()`).
   */
  mfa?: MfaState;
  /** What the session stores next to the user (`session.metadata`). */
  metadata?: Record<string, unknown>;
}

/** A TOTP or recovery code was accepted, at sign-in or for a token client. */
export interface AuthenticationMfaVerifiedEvent {
  type: 'mfa-verified';
  userId: string;
  method: 'totp' | 'recovery-code';
}

/** A code was refused. `locked` once the user reached `mfa.maxAttempts`. */
export interface AuthenticationMfaFailedEvent {
  type: 'mfa-failed';
  userId: string;
  method: 'totp' | 'recovery-code';
  /** Failures within `mfa.lockoutWindow`, this one included. */
  failures: number;
  locked: boolean;
}

/** An authenticator was confirmed: a first one, or a replacement (`replaced`). */
export interface AuthenticationMfaEnabledEvent {
  type: 'mfa-enabled';
  userId: string;
  replaced: boolean;
}

/** The authenticator and the recovery codes were removed. */
export interface AuthenticationMfaDisabledEvent {
  type: 'mfa-disabled';
  userId: string;
}

/** A new batch of recovery codes replaced the previous one. */
export interface AuthenticationRecoveryCodesGeneratedEvent {
  type: 'recovery-codes-generated';
  userId: string;
  count: number;
}

/**
 * A spent refresh token came back, so two parties hold it: the family was
 * revoked. A signal of token theft.
 */
export interface AuthenticationRefreshTokenReusedEvent {
  type: 'refresh-token-reused';
  userId: string;
  tokenFamilyId: string;
}

/**
 * A session or a token client was signed out: one session
 * (`SignInService.signOut()`, `SessionService.revoke()`), one refresh-token
 * family (`TokenService.revoke()`), or all of them (`everywhere`,
 * `SignInService.signOutEverywhere()`).
 */
export interface AuthenticationSignOutEvent {
  type: 'sign-out';
  userId: string;
  sessionId?: string;
  tokenFamilyId?: string;
  /** Every session and refresh-token family of the user. */
  everywhere?: true;
}

/**
 * Someone asked for a password reset link. `userId` is missing when no
 * account has the address: nothing was sent. Many of those from one
 * source is someone probing which addresses are registered.
 */
export interface AuthenticationPasswordResetRequestedEvent {
  type: 'password-reset-requested';
  /** Trimmed and lowercased. */
  email: string;
  userId?: string;
}

/**
 * A reset link set a new password. Every session and refresh-token family
 * of the user was ended, and the address counts as verified.
 */
export interface AuthenticationPasswordResetEvent {
  type: 'password-reset';
  userId: string;
}

/** A verification link proved the user's address. */
export interface AuthenticationEmailVerifiedEvent {
  type: 'email-verified';
  userId: string;
  email: string;
}

/**
 * A magic link came back and signed nobody in. `not-this-browser`: the
 * browser holds no transaction cookie for this link (`MagicLinkService`
 * sets one when the link is requested), so the link was opened somewhere
 * else, on another device, or planted by whoever requested it (login CSRF);
 * it stays usable where it was requested, and `consume()` threw a
 * `MagicLinkError`. The others are its `null`: `unknown`: malformed, used,
 * never issued, or presented with a cookie whose secret is not the link's.
 * `expired`: past `magicLink.ttl`. `refused`:
 * `MagicLinkHandler.resolveUser()` returned `null`, or an account whose
 * stored address is not the one the link was sent to.
 */
export interface AuthenticationMagicLinkRefusedEvent {
  type: 'magic-link-refused';
  reason: 'not-this-browser' | 'unknown' | 'expired' | 'refused';
  /** The address the link was sent to, once the link was looked up (`expired`, `refused`). */
  email?: string;
}

/**
 * A request's session was valid, but recording its activity
 * (`SessionStore.touchSession()`) failed: a lock timeout, a read-only
 * replica, an outage. The request went on with the session as read, and
 * its idle timeout did not move: unless a later request records activity,
 * the session ends at its previous idle deadline. Each request in a spell
 * of failures publishes one.
 */
export interface AuthenticationSessionTouchFailedEvent {
  type: 'session-touch-failed';
  userId: string;
  sessionId: string;
  /** What `touchSession()` rejected with. */
  error: unknown;
}

export type AuthenticationEvent =
  | AuthenticationSignInEvent
  | AuthenticationSignOutEvent
  | AuthenticationMfaVerifiedEvent
  | AuthenticationMfaFailedEvent
  | AuthenticationMfaEnabledEvent
  | AuthenticationMfaDisabledEvent
  | AuthenticationRecoveryCodesGeneratedEvent
  | AuthenticationRefreshTokenReusedEvent
  | AuthenticationPasswordResetRequestedEvent
  | AuthenticationPasswordResetEvent
  | AuthenticationEmailVerifiedEvent
  | AuthenticationMagicLinkRefusedEvent
  | AuthenticationSessionTouchFailedEvent;
