import type { MfaState, SessionExtra } from './authentication-result.interface.js';

export interface SessionRecord {
  /** SHA-256 of the cookie token. The token itself is never stored. */
  id: string;
  userId: string;
  createdAt: Date;
  /** Absolute expiry: activity never extends a session past this. */
  expiresAt: Date;
  /** Last activity, for the idle (sliding) timeout. */
  lastActiveAt: Date;
  mfa?: MfaState;
  /** App data: user agent, IP, device name, for "your sessions" pages. */
  metadata?: Record<string, unknown>;
  /**
   * Whatever `getSession()` read along with the session, typically its user
   * from the same query (`JOIN users`), handed to
   * `SessionCookieProvider.validate()` so a cookie request costs one read.
   * Typed by `sessionExtra` on `AuthenticationTypes`.
   *
   * Never stored: `SessionService` leaves it out of every `createSession()`
   * (rotations included), and `@CurrentSession()`, `request.session` and
   * `AuthenticationContext.session` don't carry it. Join fresh data on every
   * read; don't keep a copy of the user on the session row, which goes stale
   * when the user changes.
   */
  extra?: SessionExtra;
}

/**
 * Where sessions live. Implement it on your database or Redis, and register
 * the provider with `AuthenticationStorage.registerSource({ sessions: this })`.
 * Each method's comment has its rule, and `authenticationStoreContract()`
 * from `@nestjs/authentication/testing` checks them.
 *
 * Optional fields come back absent (`undefined`), never `null`. Times come
 * from `SessionService`'s clock, never the store's.
 */
export interface SessionStore {
  /**
   * The session, or `undefined`. Expired sessions may be returned: `SessionService` checks expiry.
   * May set `extra` to what the same query read with it (the user, joined), for
   * `SessionCookieProvider.validate()`.
   */
  getSession(id: string): Promise<SessionRecord | undefined>;
  /**
   * Saves a new session (a fresh random id: a plain insert). A good place
   * to delete sessions whose `expiresAt` has passed, so the store stays
   * bounded. `record` never carries `extra`.
   */
  createSession(record: SessionRecord): Promise<void>;
  /**
   * Moves `lastActiveAt` forward, **only if the session still exists** and
   * only forward: one conditional write, `UPDATE … SET last_active_at = ?
   * WHERE id = ? AND last_active_at < ?`, `SET … XX` in Redis. A read
   * followed by a write lets a request that read the session before a
   * sign-out or rotation deleted it bring it back. Changes no other field.
   */
  touchSession(id: string, lastActiveAt: Date): Promise<void>;
  /**
   * Deletes the session, and resolves whether this call deleted it: one
   * statement (`DELETE … WHERE id = ?` and its row count, Redis `DEL` and its
   * count), `false` when it was already gone. `SessionService.rotate()`
   * relies on it: of a rotation and a revocation of one session (or two
   * rotations), only one may win.
   */
  deleteSession(id: string): Promise<boolean>;
  /**
   * The user's sessions, in any order (`[]` when none), expired ones included.
   * Without `extra`: they feed "your sessions" pages.
   */
  listUserSessions(userId: string): Promise<SessionRecord[]>;
  /** Deletes every session of the user ("sign out everywhere"). */
  deleteUserSessions(userId: string): Promise<void>;
}
