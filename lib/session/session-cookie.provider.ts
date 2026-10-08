import { Inject, type ExecutionContext } from '@nestjs/common';
import { requestOf } from '../utils/auth-state.util.js';
import { AuthenticationProvider, PROVIDER_INIT, type ProviderInit } from '../providers/authentication.provider.js';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';
import type { SessionRecord } from '../interfaces/session-store.interface.js';
import { SessionService } from './session.service.js';

/**
 * Base class for cookie-session authentication. Extend it and load the
 * user; `SessionService` is property-injected, so the subclass constructor
 * only lists its own dependencies:
 *
 * ```ts
 * @Injectable()
 * export class SessionAuth extends SessionCookieProvider<User> {
 *   constructor(private readonly users: UsersRepository) { super(); }
 *   validate(session: SessionRecord) {
 *     return this.users.findById(session.userId);
 *   }
 * }
 * ```
 *
 * A store whose `getSession()` reads the user in the same query (a `JOIN`)
 * can hand it over in `session.extra`, typed by `sessionExtra` on
 * `AuthenticationTypes`, which saves the second read on every request:
 *
 * ```ts
 * validate(session: SessionRecord) {
 *   return session.extra?.user ?? null;
 * }
 * ```
 *
 * `extra` stays out of the result: `@CurrentSession()`, `request.session`
 * and `AuthenticationContext.session` get the session without it.
 *
 * A missing, stale or unknown cookie counts as "no credentials" rather than
 * a 401: browsers keep sending them, and optional routes should keep
 * working. So does the cookie on a cross-origin POST, PUT, PATCH or DELETE
 * (CSRF defence on top of `SameSite=Lax`; see `session.trustedOrigins`).
 * Works on socket.io handshakes and `ws` upgrade requests too; check
 * `Origin` in the gateway against cross-site WebSocket hijacking, since
 * browsers send cookies on cross-site upgrades.
 */
export abstract class SessionCookieProvider<TUser> extends AuthenticationProvider<TUser, SessionRecord> {
  @Inject(SessionService) protected readonly sessions!: SessionService;

  /**
   * Loads the user for a live session; `null` for deleted or banned users, which ends the session.
   * `session.extra` is what the store read with the session, if anything.
   */
  protected abstract validate(session: SessionRecord): TUser | null | undefined | Promise<TUser | null | undefined>;

  async authenticate(context: ExecutionContext): Promise<AuthenticationResult<TUser, SessionRecord> | null> {
    const session = await this.sessions.validate(this.sessions.tokenFrom(requestOf(context)));
    if (!session) {
      return null;
    }

    const user = await this.validate(session);
    if (user === null || user === undefined) {
      await this.sessions.discard(session.id);
      return null;
    }

    // What the store joined (often the user's row, password hash and all) is for `validate()` only.
    const { extra: _, ...stored } = session;
    return { user, session: stored, mfa: session.mfa };
  }

  /** @internal An instance created with `new` was not property-injected. */
  [PROVIDER_INIT](resolve: Parameters<ProviderInit>[0]) {
    (this as unknown as { sessions?: SessionService }).sessions ??= resolve(SessionService);
  }
}
