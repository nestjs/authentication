import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { AuthenticationRegistry } from '../services/authentication-registry.service.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { TOKEN_PATTERN, randomToken, sha256 } from '../utils/crypto.util.js';
import { durationOr, hasExpired } from '../utils/duration.util.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import { requireUrlOption } from '../utils/options.util.js';
import type { EmailVerificationOptions } from '../interfaces/email-verification.interface.js';
import { EmailVerificationHandler } from './email-verification.handler.js';

/**
 * Email verification links: 256-bit single-use tokens, stored hashed, bound
 * to the user and to the address they were sent to. Changing the address
 * makes the links sent to the old one verify nothing.
 *
 * Point the link at a page that POSTs the token back: mail scanners and link
 * previews follow GET links, and would use it up.
 */
@Injectable()
export class EmailVerificationService {
  private static readonly logger = new Logger('EmailVerificationService');
  private readonly options?: EmailVerificationOptions;
  private readonly ttl: number;

  constructor(
    private readonly storage: AuthenticationStorage,
    private readonly registry: AuthenticationRegistry,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { emailVerification?: EmailVerificationOptions },
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
  ) {
    this.options = options?.emailVerification;
    if (this.options) {
      requireUrlOption(this.options.url, 'emailVerification.url', 'the page that receives the link');
    }
    this.ttl = durationOr(this.options?.ttl, '24h');
  }

  /**
   * Sends a verification link for the user's current address, through
   * `EmailVerificationHandler.send()`. Call it at sign-up, when the address
   * changes, and when the user asks for a new link. The token is not returned.
   */
  async send(user: { id: string; email: string }): Promise<{ expiresAt: Date }> {
    const { options, handler } = this.feature();
    // The address as the account has it: `markVerified()` compares it with the stored one, which
    // may not be lowercase.
    if (typeof user?.email !== 'string' || user.email.trim() === '') {
      throw new TypeError('EmailVerificationService.send(): the user needs an `email` to send the link to.');
    }
    const email = user.email;

    const token = randomToken();
    const now = this.now();
    const expiresAt = new Date(now + this.ttl);
    await this.storage.emailTokens.saveEmailToken({
      id: sha256(token),
      purpose: 'email-verification',
      userId: user.id,
      email,
      createdAt: new Date(now),
      expiresAt,
    });

    const url = new URL(options.url);
    url.searchParams.set('token', token);
    await handler.send({ userId: user.id, email, url: url.toString(), expiresAt });

    return { expiresAt };
  }

  /**
   * Burns the token and asks `EmailVerificationHandler.markVerified()` to
   * record the address, if it is still the user's. Resolves the verified
   * address, or `null` for unknown, used or expired tokens and for an
   * address the user has since changed. When `markVerified()` throws, the
   * link works again until it expires, and the error is rethrown.
   */
  async verify(token: string): Promise<{ userId: string; email: string } | null> {
    const { handler } = this.feature();
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
      return null;
    }

    const record = await this.storage.emailTokens.consumeEmailToken(sha256(token), 'email-verification');
    if (!record || hasExpired(record.expiresAt, this.now())) {
      return null;
    }
    let verified: boolean;
    try {
      verified = await handler.markVerified(record.userId, record.email);
    } catch (error) {
      // Give the link back, so the user can try it again rather than ask for another email. Marking
      // an address verified twice changes nothing, and one the user changed since gets `false`.
      await this.storage.emailTokens.saveEmailToken(record).catch((saveError: unknown) =>
        EmailVerificationService.logger.error('Could not give back an email verification link', saveError instanceof Error ? saveError.stack : saveError),
      );
      throw error;
    }
    if (!verified) {
      return null;
    }

    await this.storage.emailTokens.deleteUserEmailTokens(record.userId, 'email-verification');
    this.events.emit({ type: 'email-verified', userId: record.userId, email: record.email });

    return { userId: record.userId, email: record.email };
  }

  /** The options and the handler; the module refuses to start with one and not the other. */
  private feature(): { options: EmailVerificationOptions; handler: EmailVerificationHandler } {
    const handler = this.registry.handler('emailVerification');
    if (!this.options || !handler) {
      throw new Error(
        'EmailVerificationService: email verification is not enabled. Configure `emailVerification` in the ' +
          "AuthenticationModule options, and register an EmailVerificationHandler: `registry.registerHandler('emailVerification', this)`.",
      );
    }
    return { options: this.options, handler };
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}
