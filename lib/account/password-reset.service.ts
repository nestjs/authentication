import { Inject, Injectable, Logger, Optional, type OnModuleDestroy } from '@nestjs/common';
import { AuthenticationScope } from '../context/authentication-scope.service.js';
import { AuthenticationRegistry } from '../services/authentication-registry.service.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { TOKEN_PATTERN, randomToken, safeEqual, sha256 } from '../utils/crypto.util.js';
import { durationOr, hasExpired } from '../utils/duration.util.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import { requireUrlOption } from '../utils/options.util.js';
import { TokenService } from '../jwt/token.service.js';
import { PasswordHasher, isHashablePassword } from '../services/password-hasher.service.js';
import { SessionService } from '../session/session.service.js';
import { SignInService } from '../session/sign-in.service.js';
import type {
  PasswordResetAccount,
  PasswordResetOptions,
  ResetPasswordOptions,
  PasswordResetResult,
} from '../interfaces/password-reset.interface.js';
import { isMailableEmail, normalizeEmail } from './email.util.js';
import { PasswordResetHandler } from './password-reset.handler.js';

/**
 * "Forgot your password?": reset links that are 256-bit single-use tokens,
 * stored hashed, short-lived, and bound to the address they were sent to and
 * to the password they replace.
 *
 * - `request(email)` answers the same way, at once, whether or not the
 *   address has an account: finding the account, storing the token and
 *   sending the link happen after it returned, so neither the answer nor
 *   its timing reveals which addresses are registered. The link goes to the
 *   address the account has stored, never to the one typed in the form.
 * - `reset(token, password)` burns the token, stores the new password's
 *   hash, invalidates the user's other reset links, and ends every session
 *   and refresh-token family of the user (whoever knew the old password is
 *   signed out). It also marks the address verified when email
 *   verification is configured: the link proved it. API keys live in your
 *   own table: revoke those yourself, on the `password-reset` event.
 *
 * Point the link at a page that asks for the new password and POSTs it with
 * the token: mail scanners and link previews follow GET links.
 */
@Injectable()
export class PasswordResetService implements OnModuleDestroy {
  private static readonly logger = new Logger('PasswordResetService');
  private readonly options?: PasswordResetOptions;
  private readonly ttl: number;
  private readonly inFlight = new Set<Promise<void>>();

  constructor(
    private readonly storage: AuthenticationStorage,
    private readonly registry: AuthenticationRegistry,
    private readonly hasher: PasswordHasher,
    private readonly sessions: SessionService,
    private readonly tokens: TokenService,
    private readonly signInService: SignInService,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { passwordReset?: PasswordResetOptions },
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
    private readonly scope: AuthenticationScope = new AuthenticationScope(),
  ) {
    this.options = options?.passwordReset;
    if (this.options) {
      requireUrlOption(this.options.url, 'passwordReset.url', 'the page that receives the link');
    }
    this.ttl = durationOr(this.options?.ttl, '1h');
  }

  /**
   * Starts a reset for `email`, if it belongs to an account: the link goes
   * to `PasswordResetHandler.send()`. Returns at once, before the account is
   * looked up, so the caller answers every address the same way and in the
   * same time. Failures are logged, not thrown. On shutdown, the module waits
   * for the requests in flight.
   */
  request(email: string): void {
    this.feature();
    const requested = typeof email === 'string' ? normalizeEmail(email) : '';
    if (!isMailableEmail(requested)) {
      return;
    }

    // The lookup runs once the caller has answered: even a handler that works synchronously
    // cannot make the answer, or its timing, depend on the account.
    const work = new Promise<void>((resolve) => setImmediate(resolve))
      .then(() => this.issue(requested))
      .catch((error: unknown) =>
        PasswordResetService.logger.error('A password reset request failed', error instanceof Error ? error.stack : error),
      );
    this.inFlight.add(work);
    void work.finally(() => this.inFlight.delete(work));
  }

  /**
   * Sets a new password with a reset token. `null` (and nothing changed)
   * for an unknown, used or expired token, and for one whose account
   * changed its address or password since the link was sent. `null` too,
   * before the token is looked up (so the link still works), for a password
   * `PasswordHasher` refuses: not a string, empty, or over 4 KiB. Check your
   * own password rules before calling it. With `signIn`, a request from
   * another origin than the app's own and `session.trustedOrigins` gets a
   * `ForbiddenException` first, as `SignInService.signIn()` does, so the link
   * and the password stay as they were. Without `signIn`, the origin is not
   * checked.
   */
  async reset(token: string, password: string, { signIn = false }: ResetPasswordOptions = {}): Promise<PasswordResetResult | null> {
    const { handler } = this.feature();
    // Signing in would refuse this request at the end, after the link is spent and the password
    // changed: refuse it before, whatever the token is.
    if (signIn) {
      this.signInService.refuseCrossOrigin(this.scope.exchange()?.request);
    }
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token) || !isHashablePassword(password)) {
      return null;
    }

    const record = await this.storage.emailTokens.consumeEmailToken(sha256(token), 'password-reset');
    if (!record || hasExpired(record.expiresAt, this.now())) {
      return null;
    }
    const found = await handler.findUser(normalizeEmail(record.email));
    const account = found && checked(found);
    if (
      !account ||
      account.id !== record.userId ||
      account.email !== record.email ||
      !safeEqual(fingerprint(account.passwordHash), record.fingerprint ?? '')
    ) {
      return null;
    }

    const passwordHash = await this.hasher.hash(password);
    // Sign-ins end before the new password is stored, so a store that fails leaves the old password
    // without its sessions rather than the new one next to them; and again after, for any sign-in
    // that started in between.
    await this.revokeSignIns(account.id);
    await handler.updatePassword(account.id, passwordHash);
    await this.storage.emailTokens.deleteUserEmailTokens(account.id, 'password-reset');
    await this.revokeSignIns(account.id);
    // The link reached the address, and the password is the owner's now.
    await this.registry.handler('emailVerification')?.markVerified(account.id, account.email);
    this.events.emit({ type: 'password-reset', userId: account.id });

    const signedIn = signIn ? await this.signInService.signIn(account.id, { method: 'password-reset' }) : undefined;
    return { userId: account.id, ...(signedIn && { signedIn }) };
  }

  async onModuleDestroy() {
    await Promise.all(this.inFlight);
  }

  private async issue(requested: string): Promise<void> {
    const { options, handler } = this.feature();
    const found = await handler.findUser(requested);
    if (!found) {
      this.events.emit({ type: 'password-reset-requested', email: requested });
      return;
    }
    const account = checked(found);

    const token = randomToken();
    const now = this.now();
    const expiresAt = new Date(now + this.ttl);
    await this.storage.emailTokens.saveEmailToken({
      id: sha256(token),
      purpose: 'password-reset',
      userId: account.id,
      email: account.email,
      fingerprint: fingerprint(account.passwordHash),
      createdAt: new Date(now),
      expiresAt,
    });
    this.events.emit({ type: 'password-reset-requested', email: requested, userId: account.id });

    // To the address the account has stored, never to the one typed: a lookup that ignores accents
    // or dots would otherwise mail `victim@example.com`'s link to whoever typed `victim@exämple.com`.
    const url = new URL(options.url);
    url.searchParams.set('token', token);
    await handler.send({ userId: account.id, email: account.email, url: url.toString(), expiresAt });
  }

  /** Ends every session and refresh-token family (with refresh tokens on) of the user. */
  private async revokeSignIns(userId: string) {
    await this.sessions.revokeAll(userId);
    await this.tokens.revokeAll(userId);
  }

  /** The options and the handler; the module refuses to start with one and not the other. */
  private feature(): { options: PasswordResetOptions; handler: PasswordResetHandler } {
    const handler = this.registry.handler('passwordReset');
    if (!this.options || !handler) {
      throw new Error(
        'PasswordResetService: password reset is not enabled. Configure `passwordReset` in the AuthenticationModule ' +
          "options, and register a PasswordResetHandler: `registry.registerHandler('passwordReset', this)`.",
      );
    }
    return { options: this.options, handler };
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}

/**
 * The account `findUser()` returned, with what a link is bound to: the
 * address it goes to, and the password hash it replaces. A query that leaves
 * either out would send links to the typed address, or keep them working
 * after a password change.
 */
function checked(account: PasswordResetAccount): PasswordResetAccount {
  if (typeof account.email !== 'string' || account.email.trim() === '') {
    throw new TypeError(
      'PasswordResetHandler.findUser() must return the account’s stored `email`: the link goes there, never to the ' +
        'address typed in the form.',
    );
  }
  if (account.passwordHash === undefined) {
    throw new TypeError(
      'PasswordResetHandler.findUser() must return `passwordHash` (`null` for an account without a password): a link ' +
        'works only while it is unchanged. Does the query leave the column out (TypeORM `select: false`)?',
    );
  }
  return account;
}

/** What a reset link remembers of the password it replaces. */
function fingerprint(passwordHash: string | null): string {
  return sha256(`nestjs-authentication password-reset v1 ${passwordHash ?? ''}`);
}
