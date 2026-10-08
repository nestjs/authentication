import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { firstHeader } from '../utils/auth-state.util.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { isCrossOriginWrite, normalizeOrigin } from '../utils/cross-origin.util.js';
import { TOKEN_PATTERN, randomToken, sha256 } from '../utils/crypto.util.js';
import { durationOr, hasExpired } from '../utils/duration.util.js';
import type { Duration } from '../interfaces/duration.interface.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import type { MfaState } from '../interfaces/authentication-result.interface.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import type { SessionRecord } from '../interfaces/session-store.interface.js';
import type { SessionRequest, SessionOptions, IssuedSession } from '../interfaces/session.interface.js';
import { assertCookieAttributes, defaultCookieName, readCookie, serializeCookie } from './cookies.util.js';

type RequestHeaders = Record<string, string | string[] | undefined>;

/**
 * Server-side sessions: opaque 256-bit tokens in an `HttpOnly` cookie,
 * stored by their SHA-256.
 *
 * - Absolute expiry plus an idle (sliding) timeout.
 * - `list()`, `revoke()` and `revokeAll()` for "your devices" pages and
 *   "sign out everywhere".
 * - `create()`, `validate()` and `rotate()` are the low-level operations
 *   behind `SignInService`, which also reads and writes the cookie.
 */
@Injectable()
export class SessionService {
  private static readonly logger = new Logger('SessionService');
  private readonly options: SessionOptions;
  private readonly absoluteTtl: number;
  private readonly pendingTtl: number;
  private readonly idleTtl: number;
  private readonly touchInterval: number;
  private readonly cookieName: string;
  private readonly trustedOrigins: ReadonlySet<string>;

  constructor(
    private readonly storage: AuthenticationStorage,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { session?: SessionOptions; mfa?: { pendingTtl?: Duration } },
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
  ) {
    this.options = options?.session ?? {};
    this.absoluteTtl = durationOr(this.options.absoluteTtl, '7d');
    // A pending session never outlives a verified one would.
    this.pendingTtl = Math.min(durationOr(options?.mfa?.pendingTtl, '10m'), this.absoluteTtl);
    this.idleTtl = durationOr(this.options.idleTtl, '1d');
    this.touchInterval = durationOr(this.options.touchInterval, '1m');
    // Activity is recorded at most once per touchInterval: at or past idleTtl, a user active all
    // along would be signed out as idle.
    if (this.idleTtl > 0 && this.touchInterval >= this.idleTtl) {
      throw new TypeError(
        `session.touchInterval (${this.touchInterval} ms) must be shorter than session.idleTtl (${this.idleTtl} ms): ` +
          'activity is recorded at most once per touchInterval, so active users would be signed out as idle.',
      );
    }

    this.cookieName = this.options.cookieName ?? defaultCookieName('sid', this.options.cookie);
    assertCookieAttributes(this.cookieName, this.options.cookie, 'session');

    this.trustedOrigins = new Set(
      (this.options.trustedOrigins ?? []).map((origin) => normalizeOrigin(origin, 'session.trustedOrigins')),
    );
  }

  /**
   * Starts a session. `replacing` is the token of the session this client
   * had before; it is deleted (session fixation defence). An `mfa: 'pending'`
   * session expires after `mfa.pendingTtl` (default `'10m'`) instead of
   * `absoluteTtl`: `rotate()` to `mfa: 'verified'` gives it the full
   * lifetime, counted from its creation.
   */
  async create(
    userId: string,
    { mfa, metadata, replacing }: { mfa?: MfaState; metadata?: Record<string, unknown>; replacing?: string } = {},
  ): Promise<IssuedSession> {
    if (replacing && TOKEN_PATTERN.test(replacing)) {
      await this.storage.sessions.deleteSession(sha256(replacing));
    }

    const now = this.now();
    return this.issue({
      userId,
      createdAt: new Date(now),
      expiresAt: new Date(now + (mfa === 'pending' ? this.pendingTtl : this.absoluteTtl)),
      lastActiveAt: new Date(now),
      ...(mfa && { mfa }),
      ...(metadata && { metadata }),
    });
  }

  /**
   * The live session for a token, sliding its idle timeout. Sliding is
   * best-effort: when the store fails to record the activity, the session
   * is still returned, as read (see `SessionStore.touchSession()`).
   */
  async validate(token: string | undefined): Promise<SessionRecord | null> {
    if (!token || !TOKEN_PATTERN.test(token)) {
      return null;
    }

    const record = await this.storage.sessions.getSession(sha256(token));
    if (!record) {
      return null;
    }

    const now = this.now();
    if (!this.isLive(record, now)) {
      // Past its absolute expiry, nothing can revive it. Idle, it is only idle as this read saw
      // it: another request (another instance's clock) may have touched it since, so it stays;
      // the store prunes it once its absolute expiry passes.
      if (hasExpired(record.expiresAt, now)) {
        await this.storage.sessions.deleteSession(record.id);
      }
      return null;
    }

    if (now - record.lastActiveAt.getTime() >= this.touchInterval) {
      await this.touch(record, new Date(now));
    }

    return record;
  }

  /**
   * Replaces the session id, keeping its user and absolute expiry. For
   * privilege changes; `SignInService.rotateSession()` does it for the
   * current browser and updates its cookie. A pending session rotated to
   * `mfa: 'verified'` gets the absolute lifetime a verified sign-in has,
   * `absoluteTtl` from its creation, in place of its `mfa.pendingTtl`.
   * Resolves `null` when the session was gone by the time it was replaced:
   * revoked (a sign-out everywhere, a password reset) or rotated by another
   * request, which leaves no new session behind.
   */
  async rotate(
    session: SessionRecord,
    changes: Pick<Partial<SessionRecord>, 'mfa' | 'metadata'> = {},
  ): Promise<IssuedSession | null> {
    const { id: _, ...rest } = session;
    const verifying = session.mfa === 'pending' && changes.mfa === 'verified';
    // The new session first, then the old one, which must still be there to delete: if a revocation
    // took it meanwhile (deleting the user's sessions, this new one included, or not yet), or another
    // rotation did, this one lost, and its new session must not outlive the old.
    const issued = await this.issue({
      ...rest,
      ...changes,
      lastActiveAt: new Date(this.now()),
      ...(verifying && { expiresAt: new Date(session.createdAt.getTime() + this.absoluteTtl) }),
    });
    if (!(await this.storage.sessions.deleteSession(session.id))) {
      await this.storage.sessions.deleteSession(issued.session.id);
      return null;
    }
    return issued;
  }

  /**
   * Ends one of `userId`'s sessions. Resolves `false` when the id is unknown
   * or belongs to another user, so a route can pass an id from the URL
   * without checking ownership first.
   */
  async revoke(sessionId: string, { userId }: { userId: string }): Promise<boolean> {
    const record = typeof sessionId === 'string' ? await this.storage.sessions.getSession(sessionId) : undefined;
    if (!record || record.userId !== userId) {
      return false;
    }
    await this.storage.sessions.deleteSession(record.id);
    this.events.emit({ type: 'sign-out', userId, sessionId: record.id });
    return true;
  }

  /** Ends every session of a user, optionally keeping one (`except`: its id). */
  async revokeAll(userId: string, { except }: { except?: string } = {}): Promise<void> {
    const store = this.storage.sessions;
    if (!except) {
      return store.deleteUserSessions(userId);
    }
    for (const session of await store.listUserSessions(userId)) {
      if (session.id !== except) {
        await store.deleteSession(session.id);
      }
    }
  }

  /** Live sessions of a user: not past their absolute expiry or their idle timeout. */
  async list(userId: string): Promise<SessionRecord[]> {
    const now = this.now();
    return (await this.storage.sessions.listUserSessions(userId)).filter((s) => this.isLive(s, now));
  }

  /**
   * @internal The session token a request carries. The cookie is ignored on
   * unsafe requests (and WebSocket handshakes) from another origin: see
   * {@link isCrossOriginWrite}.
   */
  tokenFrom(request: { headers: RequestHeaders; method?: string } | undefined): string | undefined {
    if (!request || this.isCrossOriginWrite(request)) {
      return undefined;
    }
    const token = readCookie(firstHeader(request.headers, 'cookie'), this.cookieName);
    return token && TOKEN_PATTERN.test(token) ? token : undefined;
  }

  /** @internal Whether `request` changes state from another origin than the app's own and `trustedOrigins`. */
  isCrossOriginWrite(request: { headers: RequestHeaders; method?: string }): boolean {
    return isCrossOriginWrite(request, this.trustedOrigins);
  }

  /** @internal */
  metadataFor(request: SessionRequest | undefined): Record<string, unknown> | undefined {
    return request && this.options.metadata ? this.options.metadata(request) : undefined;
  }

  /** @internal */
  clearCookie(): string {
    return serializeCookie(this.cookieName, '', { ...this.options.cookie, maxAge: 0 });
  }

  /** @internal Deletes a session by id, for sessions whose user is gone. */
  async discard(sessionId: string): Promise<void> {
    await this.storage.sessions.deleteSession(sessionId);
  }

  /**
   * Records activity, best-effort: the session was read live, so a failed write (a lock timeout,
   * a read-only replica) does not fail the request. It is logged and published as
   * `session-touch-failed`, and the session keeps the idle deadline the store still has.
   */
  private async touch(record: SessionRecord, lastActiveAt: Date): Promise<void> {
    try {
      await this.storage.sessions.touchSession(record.id, lastActiveAt);
    } catch (error) {
      SessionService.logger.warn(
        `Recording activity on a session of user ${record.userId} failed, so its idle timeout did not move: ` +
          (error instanceof Error ? error.message : String(error)),
      );
      this.events.emit({ type: 'session-touch-failed', userId: record.userId, sessionId: record.id, error });
      return;
    }
    record.lastActiveAt = lastActiveAt;
  }

  private isLive(record: SessionRecord, now: number): boolean {
    if (hasExpired(record.expiresAt, now)) {
      return false;
    }
    return this.idleTtl === 0 || now < record.lastActiveAt.getTime() + this.idleTtl;
  }

  private async issue(fields: Omit<SessionRecord, 'id'>): Promise<IssuedSession> {
    const token = randomToken();
    const session: SessionRecord = { id: sha256(token), ...fields };
    await this.storage.sessions.createSession(session);
    const maxAge = Math.round((session.expiresAt.getTime() - this.now()) / 1000);
    return { session, token, cookie: serializeCookie(this.cookieName, token, { ...this.options.cookie, maxAge }) };
  }

  private now() {
    return this.options.now?.() ?? Date.now();
  }
}
