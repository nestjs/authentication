import { ForbiddenException, Injectable, Optional } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { AuthenticationScope, type HttpExchange } from '../context/authentication-scope.service.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import { TokenService } from '../jwt/token.service.js';
import { MfaService } from '../mfa/mfa.service.js';
import type { IssuedSession } from '../interfaces/session.interface.js';
import type { SignInOptions } from '../interfaces/sign-in-options.interface.js';
import { sha256 } from '../utils/crypto.util.js';
import { SessionService } from './session.service.js';

/**
 * The browser's side of signing in. Called from an HTTP handler (or a
 * GraphQL resolver whose context has `req` and `res`), each method reads
 * this browser's session cookie from the request and sets the new one on
 * the response, on Express and Fastify alike. Elsewhere, nothing is read or
 * set: send the returned `cookie` yourself.
 *
 * `signIn()` is the one place a first factor (password, magic link, OIDC)
 * turns into a session:
 * - a sign-in posted from another origin's page is refused with a 403
 *   (login CSRF: signing the victim's browser in to the attacker's
 *   account), by the same rule as `app.enableCsrfProtection()`;
 * - the browser's previous session is deleted (session fixation defence);
 * - with `mfa` configured, users with a confirmed authenticator get an
 *   `mfa: 'pending'` session, which is not signed in anywhere until
 *   `completeMfa()` verifies a code.
 */
@Injectable()
export class SignInService {
  constructor(
    private readonly sessions: SessionService,
    private readonly mfa: MfaService,
    private readonly tokens: TokenService,
    private readonly scope: AuthenticationScope = new AuthenticationScope(),
    @Optional() private readonly adapterHost?: HttpAdapterHost,
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
  ) {}

  /**
   * Signs the user in on this browser. Throws a `ForbiddenException` for a
   * request that changes state from another origin than the app's own and
   * `session.trustedOrigins`.
   */
  async signIn(userId: string, { method, metadata }: SignInOptions = {}): Promise<IssuedSession> {
    const exchange = this.scope.exchange();
    this.refuseCrossOrigin(exchange?.request);

    const mfa = (await this.mfa.isEnrolled(userId)) ? 'pending' : undefined;
    const stored = { ...this.sessions.metadataFor(exchange?.request), ...metadata };
    const issued = await this.sessions.create(userId, {
      mfa,
      metadata: Object.keys(stored).length ? stored : undefined,
      replacing: this.sessions.tokenFrom(exchange?.request),
    });
    this.setCookie(exchange, issued.cookie);

    this.events.emit({
      type: 'sign-in',
      userId,
      sessionId: issued.session.id,
      ...(method && { method }),
      ...(mfa && { mfa }),
      ...(issued.session.metadata && { metadata: issued.session.metadata }),
    });

    return issued;
  }

  /**
   * Completes the second factor of this browser's session with a TOTP code
   * or a recovery code, and rotates the session to `mfa: 'verified'` under a
   * new id. `null` when the browser has no session or the code is wrong. A
   * request with neither counts nothing against the user's lockout, as
   * `TokenService.issue()` without a `secondFactor` doesn't.
   */
  async completeMfa({ code, recoveryCode }: { code?: string; recoveryCode?: string }): Promise<IssuedSession | null> {
    if (!code && !recoveryCode) {
      return null;
    }

    const exchange = this.scope.exchange();
    const session = await this.sessions.validate(this.sessions.tokenFrom(exchange?.request));
    if (!session) {
      return null;
    }

    const verified = recoveryCode
      ? await this.mfa.verifyRecoveryCode(session.userId, recoveryCode)
      : await this.mfa.verifyTotp(session.userId, code!);
    if (!verified) {
      return null;
    }

    // A revocation that took the session meanwhile wins: no verified session comes of it.
    const issued = await this.sessions.rotate(session, { mfa: 'verified' });
    if (issued) {
      this.setCookie(exchange, issued.cookie);
    }
    return issued;
  }

  /**
   * Confirms the user's new authenticator with a code from it
   * (`MfaService.confirm()`), and, when this browser holds a session of the
   * user, rotates it to `mfa: 'verified'` under a new id: the code proved
   * this browser has the authenticator, so the user isn't asked for another
   * code until their next sign-in. Without such a session (a token client,
   * another user's session), it only confirms. `false` when the code is
   * wrong, and nothing changes.
   */
  async confirmMfa(userId: string, code: string): Promise<boolean> {
    if (!(await this.mfa.confirm(userId, code))) {
      return false;
    }

    const exchange = this.scope.exchange();
    const session = await this.sessions.validate(this.sessions.tokenFrom(exchange?.request));
    if (session?.userId === userId) {
      const issued = await this.sessions.rotate(session, { mfa: 'verified' });
      if (issued) {
        this.setCookie(exchange, issued.cookie);
      }
    }

    return true;
  }

  /**
   * Gives this browser's session a new id, keeping its user, expiry and
   * second factor, and updates the cookie. Call it on privilege changes: a
   * new password, a new role. `null` when the browser has no session, or
   * lost it meanwhile (revoked, or rotated by another request).
   */
  async rotateSession(): Promise<IssuedSession | null> {
    const exchange = this.scope.exchange();
    const session = await this.sessions.validate(this.sessions.tokenFrom(exchange?.request));
    if (!session) {
      return null;
    }
    const issued = await this.sessions.rotate(session);
    if (issued) {
      this.setCookie(exchange, issued.cookie);
    }
    return issued;
  }

  /**
   * Ends this browser's session, pending or not, and clears its cookie.
   * `false` when the browser had no live session (a bearer-token client, an
   * expired cookie).
   */
  async signOut(): Promise<boolean> {
    const exchange = this.scope.exchange();
    const token = this.sessions.tokenFrom(exchange?.request);
    if (!token) {
      return false;
    }

    const session = await this.sessions.validate(token);
    this.setCookie(exchange, this.sessions.clearCookie());
    // Deleted whatever this instance makes of it: idle here, it may still be live for another
    // instance (its clock, or another idleTtl during a rolling deploy).
    await this.sessions.discard(sha256(token));
    if (!session) {
      return false;
    }

    this.events.emit({ type: 'sign-out', userId: session.userId, sessionId: session.id });
    return true;
  }

  /**
   * Ends every session and, with `accessToken` configured, every
   * refresh-token family of the user, and clears this browser's cookie if it
   * was one of them. API keys live in your own table: revoke those yourself.
   */
  async signOutEverywhere(userId: string): Promise<void> {
    const exchange = this.scope.exchange();
    const own = await this.sessions.validate(this.sessions.tokenFrom(exchange?.request));
    await this.sessions.revokeAll(userId);
    await this.tokens.revokeAll(userId);
    if (own?.userId === userId) {
      this.setCookie(exchange, this.sessions.clearCookie());
    }
    this.events.emit({ type: 'sign-out', userId, everywhere: true });
  }

  /**
   * @internal The 403 `signIn()` answers a request that changes state from
   * another origin than the app's own and `session.trustedOrigins` with.
   * What binds a sign-in to a browser (a magic link's `create()`) checks it
   * too: another site's page must not start one in the victim's browser.
   */
  refuseCrossOrigin(request: HttpExchange['request'] | undefined): void {
    if (request && this.sessions.isCrossOriginWrite(request)) {
      throw new ForbiddenException('Cross-origin sign-in refused');
    }
  }

  private setCookie(exchange: HttpExchange | undefined, cookie: string) {
    if (exchange?.response) {
      this.adapterHost?.httpAdapter?.appendHeader(exchange.response, 'Set-Cookie', cookie);
    }
  }
}
