import { randomBytes, randomInt, scrypt } from 'node:crypto';
import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { safeEqual } from '../utils/crypto.util.js';
import { durationOr } from '../utils/duration.util.js';
import { requireIntegerOption } from '../utils/options.util.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import type { MfaStore } from '../interfaces/mfa-store.interface.js';
import { SecretDecryptionError } from '../errors/secret-decryption.error.js';
import type { MfaOptions } from '../interfaces/mfa-options.interface.js';
import { MfaAlreadyEnrolledError } from '../errors/mfa-already-enrolled.error.js';
import { base32Decode, base32Encode, hotp, totpStep } from './otp.util.js';
import { SecretCipher } from './secret-cipher.service.js';

const PERIOD = 30;
const DIGITS = 6;
// Crockford-style alphabet: no 0/O or 1/I/L confusion.
const CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * A recovery code as stored: scrypt (N=2^14, r=8, p=1, 16 MiB), salted with
 * the user id. The salt is deterministic so the store can still look codes
 * up by hash (`consumeRecoveryCode` is an atomic delete), and per user, so a
 * dump has to be attacked one user at a time. A code carries ~49 bits:
 * cheap to exhaust at SHA-256 speed, decades per user at this cost.
 */
function hashRecoveryCode(userId: string, normalized: string): Promise<string> {
  const salt = `nestjs-authentication recovery-code v1 ${userId}`;
  return new Promise((resolve, reject) =>
    scrypt(normalized, salt, 32, { N: 2 ** 14, r: 8, p: 1 }, (error, key) =>
      error ? reject(error) : resolve(`rc1.${key.toString('base64url')}`),
    ),
  );
}

type Method = 'totp' | 'recovery-code';

/**
 * TOTP second factor (RFC 6238 over RFC 4226 HOTP, SHA-1, 6 digits, 30 s:
 * the parameters every authenticator app supports) plus recovery codes.
 *
 * - `enroll()` stores an unconfirmed 160-bit secret and returns the
 *   `otpauth://` URI for the QR code; `confirm()` activates it once a
 *   code verifies. It refuses to touch a confirmed authenticator
 *   ({@link MfaAlreadyEnrolledError}): replacing one takes
 *   `{ replace: true }`, which stages the new secret while the current one
 *   keeps working until `confirm()`. Call that only from a route that
 *   requires a verified second factor (`@Authenticate({ mfa: true })`), or
 *   remove the authenticator with `disable()` first.
 * - Secrets are encrypted before they reach the store (AES-256-GCM, bound to
 *   the user id) and decrypted only to compute codes. A secret encrypted with
 *   an older key is re-encrypted with the current one after its next
 *   successful verification, or by `reencrypt(userId)`.
 * - Each time step is accepted once per user (replay protection), across
 *   the ±`window` range.
 * - After `maxAttempts` failures in `lockoutWindow` every check fails;
 *   6 digits are otherwise brute-forceable. Each attempt is counted before
 *   it is checked, so a burst of parallel guesses cannot outrun the limit.
 *   This is a per-account control on the verifier, not request rate
 *   limiting.
 * - Recovery codes are shown once, and stored under a slow hash salted
 *   with the user id (~49 bits of entropy each, plus the attempt limit).
 */
@Injectable()
export class MfaService {
  private static readonly logger = new Logger('MfaService');
  private readonly options?: MfaOptions;
  private readonly cipher?: SecretCipher;
  private readonly lockoutWindow: number;

  constructor(
    private readonly storage: AuthenticationStorage,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { mfa?: MfaOptions },
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
  ) {
    this.options = options?.mfa;
    this.lockoutWindow = durationOr(this.options?.lockoutWindow, '15m');

    if (!this.options) {
      return; // MFA off: isEnrolled() answers false, everything else throws, and the store is never read
    }

    if (this.options.encryption === undefined) {
      throw new Error(
        'MFA: `mfa.encryption` is required. TOTP secrets cannot be hashed, so a store dump would let anyone ' +
          'mint valid codes. Pass `{ keys: [key] }`, or `false` to store them in plaintext deliberately.',
      );
    }

    if (this.options.encryption) {
      this.cipher = new SecretCipher(this.options.encryption);
    }

    // A `NaN` limit would never be reached: every guess would be checked.
    requireIntegerOption(this.options.maxAttempts, 'mfa.maxAttempts', { min: 1 });
    // Each step either side adds two codes that every guess may hit; 30 would be seconds, not steps.
    requireIntegerOption(this.options.window, 'mfa.window', { min: 0, max: 10 });
    requireIntegerOption(this.options.recoveryCodes, 'mfa.recoveryCodes', { min: 1 });
  }

  /**
   * Whether the user has a confirmed authenticator. Without the `mfa`
   * option, MFA is off: `false`, without reading the store, even for a user
   * who enrolled through another app sharing the user database. Every app
   * that signs those users in must configure `mfa` if any of them does.
   */
  async isEnrolled(userId: string): Promise<boolean> {
    if (!this.options) {
      return false;
    }
    // Truthy, not `=== true`: a store that reads the flag back as `1` must not skip the second factor.
    return !!(await this.store.getTotp(userId))?.confirmed;
  }

  /**
   * Starts an enrollment. Throws {@link MfaAlreadyEnrolledError} when the user
   * has a confirmed authenticator, unless `replace` is set: then the new
   * secret is staged and the current authenticator stays active until
   * `confirm()` succeeds with a code from the new one.
   */
  async enroll(
    userId: string,
    accountName: string,
    { replace = false }: { replace?: boolean } = {},
  ): Promise<{ secret: string; uri: string }> {
    const current = await this.store.getTotp(userId);
    const secret = base32Encode(randomBytes(20));
    const sealed = this.seal(userId, secret);

    if (current?.confirmed) {
      if (!replace) {
        throw new MfaAlreadyEnrolledError(userId);
      }
      await this.store.saveTotp(userId, { ...current, pendingSecret: sealed });
    } else {
      await this.store.saveTotp(userId, { secret: sealed, confirmed: false });
    }

    return { secret, uri: this.keyUri(secret, accountName) };
  }

  /**
   * Activates a pending enrollment (or a staged replacement, which then
   * takes the place of the current authenticator).
   */
  async confirm(userId: string, code: string): Promise<boolean> {
    const record = await this.store.getTotp(userId);
    const candidate = record?.confirmed ? record.pendingSecret : record?.secret;
    if (!record || !candidate) {
      return false;
    }

    const opened = this.open(userId, candidate);
    if (!opened || !(await this.check(userId, opened, code))) {
      return false;
    }

    // Read again: it carries the step just claimed, and a disable() or re-enrollment meanwhile wins.
    const latest = await this.store.getTotp(userId);
    const stillPending = !!latest && (record.confirmed ? latest.pendingSecret === candidate : latest.secret === candidate);
    if (!latest || !stillPending) {
      return false; // re-enrolled or disabled concurrently
    }

    const { pendingSecret: _, ...rest } = latest;
    const secret = opened.needsReencrypt ? this.seal(userId, opened.plaintext) : candidate;
    await this.store.saveTotp(userId, { ...rest, secret, confirmed: true });
    this.events.emit({ type: 'mfa-enabled', userId, replaced: record.confirmed });
    return true;
  }

  async verifyTotp(userId: string, code: string): Promise<boolean> {
    const record = await this.store.getTotp(userId);
    if (!record?.confirmed) {
      return false;
    }

    const opened = this.open(userId, record.secret);
    if (!opened || !(await this.check(userId, opened, code))) {
      return false;
    }

    if (opened.needsReencrypt) {
      // Read again: it keeps the claimed step, and an authenticator disabled or replaced meanwhile stays so.
      const latest = await this.store.getTotp(userId);
      if (latest?.secret === record.secret) {
        await this.store.saveTotp(userId, { ...latest, secret: this.seal(userId, opened.plaintext) });
      }
    }

    this.events.emit({ type: 'mfa-verified', userId, method: 'totp' });
    return true;
  }

  /**
   * Re-encrypts the stored secret with the current key if it was sealed
   * with an older one (or is legacy plaintext under `migratePlaintext`).
   * For key-rotation jobs; returns whether anything was rewritten.
   */
  async reencrypt(userId: string): Promise<boolean> {
    const record = await this.store.getTotp(userId);
    if (!record || !this.cipher || !this.cipher.needsReencrypt(record.secret)) {
      return false;
    }

    const opened = this.open(userId, record.secret);
    if (!opened) {
      return false;
    }

    // Read again before writing: a disable() or a confirmed replacement meanwhile must stay.
    const latest = await this.store.getTotp(userId);
    if (latest?.secret !== record.secret) {
      return false;
    }
    await this.store.saveTotp(userId, { ...latest, secret: this.seal(userId, opened.plaintext) });
    return true;
  }

  /**
   * Returns fresh plaintext codes (show once); replaces any previous batch.
   * Codes are a second factor: for a user with a confirmed authenticator,
   * call it right after `confirm()` succeeded, or from a route that requires
   * a verified second factor (`@Authenticate({ mfa: true })`). Otherwise an
   * API key, or a token issued before the user enrolled, could mint codes
   * that finish a sign-in with the password alone.
   */
  async generateRecoveryCodes(userId: string): Promise<string[]> {
    const codes = Array.from({ length: this.options?.recoveryCodes ?? 10 }, () => {
      const chars = Array.from({ length: 10 }, () => CODE_ALPHABET[randomInt(CODE_ALPHABET.length)]).join('');
      return `${chars.slice(0, 5)}-${chars.slice(5)}`;
    });

    const hashes = await Promise.all(codes.map((c) => hashRecoveryCode(userId, normalizeCode(c))));
    await this.store.saveRecoveryCodes(userId, hashes);
    this.events.emit({ type: 'recovery-codes-generated', userId, count: codes.length });
    return codes;
  }

  async verifyRecoveryCode(userId: string, code: string): Promise<boolean> {
    const attempt = await this.begin(userId, 'recovery-code');
    if (attempt === undefined) {
      return false;
    }

    const normalized = typeof code === 'string' ? normalizeCode(code) : '';
    if (
      normalized.length === 10 &&
      (await this.store.consumeRecoveryCode(userId, await hashRecoveryCode(userId, normalized)))
    ) {
      await this.store.clearMfaFailures(userId);
      this.events.emit({ type: 'mfa-verified', userId, method: 'recovery-code' });
      return true;
    }

    this.failed(userId, 'recovery-code', attempt);
    return false;
  }

  async remainingRecoveryCodes(userId: string): Promise<number> {
    return this.store.countRecoveryCodes(userId);
  }

  /**
   * Removes the authenticator and the recovery codes. Call it only from a
   * route that requires a verified second factor
   * (`@Authenticate({ mfa: true })`): an API key, or a token issued before
   * the user enrolled, is no second factor.
   */
  async disable(userId: string): Promise<void> {
    await this.store.saveTotp(userId, null);
    await this.store.saveRecoveryCodes(userId, []);
    this.events.emit({ type: 'mfa-disabled', userId });
  }

  keyUri(secret: string, accountName: string): string {
    const issuer = this.options?.issuer ?? 'NestJS';
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
    const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(PERIOD) });
    return `otpauth://totp/${label}?${params}`;
  }

  /** `opened` is undefined when the secret could not be decrypted: fail closed, not counted against the user. */
  private async check(userId: string, opened: { plaintext: string }, code: string): Promise<boolean> {
    const attempt = await this.begin(userId, 'totp');
    if (attempt === undefined) {
      return false;
    }

    const step = this.matchingStep(opened.plaintext, code);
    if (step !== undefined && (await this.store.claimTotpStep(userId, step))) {
      await this.store.clearMfaFailures(userId);
      return true;
    }

    this.failed(userId, 'totp', attempt);
    return false;
  }

  /**
   * Counts an attempt before it is checked, and returns its number within
   * the window, or `undefined` when it must be refused unchecked. Counting
   * first is what stops a burst of parallel guesses: each one gets its own
   * number from the store, and only the first `maxAttempts` are checked.
   * An attempt made while already locked out is not counted, so the lockout
   * ends `lockoutWindow` after it began.
   */
  private async begin(userId: string, method: Method): Promise<number | undefined> {
    const failures = await this.store.countMfaFailures(userId, this.lockoutWindow, this.now());
    if (failures >= this.maxAttempts) {
      this.events.emit({ type: 'mfa-failed', userId, method, failures, locked: true });
      return undefined;
    }

    const attempt = await this.store.recordMfaFailure(userId, this.lockoutWindow, this.now());
    if (attempt > this.maxAttempts) {
      this.events.emit({ type: 'mfa-failed', userId, method, failures: attempt, locked: true });
      return undefined;
    }

    return attempt;
  }

  /** The attempt was already counted by {@link begin}; this reports it. */
  private failed(userId: string, method: Method, attempt: number) {
    this.events.emit({ type: 'mfa-failed', userId, method, failures: attempt, locked: attempt >= this.maxAttempts });
  }

  private seal(userId: string, secret: string): string {
    return this.cipher ? this.cipher.encrypt(secret, `totp.${userId}`) : secret;
  }

  private open(userId: string, stored: string): { plaintext: string; needsReencrypt: boolean } | undefined {
    if (!this.cipher) {
      return { plaintext: stored, needsReencrypt: false };
    }

    try {
      return this.cipher.decrypt(stored, `totp.${userId}`);
    } catch (error) {
      if (!(error instanceof SecretDecryptionError)) {
        throw error;
      }
      // Tampering, a row copied from another user, or a key removed too early.
      MfaService.logger.error(`TOTP secret of user ${userId} could not be decrypted: ${error.message}`);
      return undefined;
    }
  }

  private matchingStep(secret: string, code: string): number | undefined {
    if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      return undefined;
    }

    let key: Buffer;
    try {
      key = base32Decode(secret);
    } catch {
      return undefined; // not a base32 secret (e.g. ciphertext stored while `encryption: false`)
    }
    // RFC 4226 §4 asks for 128 bits at least (enroll() makes 160): an empty secret (a NULL column
    // read back as '') would give codes anyone can compute.
    if (key.length < 16) {
      return undefined;
    }

    const current = totpStep(Math.floor(this.now() / 1000), PERIOD);
    const window = this.options?.window ?? 1;
    let found: number | undefined;
    // Check every candidate (no early exit) so timing does not reveal which step matched.
    for (let step = current - window; step <= current + window; step++) {
      if (safeEqual(hotp(key, step, DIGITS), code) && found === undefined) {
        found = step;
      }
    }

    return found;
  }

  /**
   * Read at each call, never in the constructor: the registry locks once the
   * module starts. Without the `mfa` option it throws before reading: MFA is
   * off, and the production guard asks for no `MfaStore`.
   */
  private get store(): MfaStore {
    if (!this.options) {
      throw new Error('MFA is not configured: add `mfa: { encryption: … }` to the AuthenticationModule options');
    }
    return this.storage.mfa;
  }

  private get maxAttempts() {
    return this.options?.maxAttempts ?? 5;
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}

function normalizeCode(code: string): string {
  return code.toUpperCase().replace(/[\s-]/g, '');
}
