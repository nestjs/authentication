import type { PasswordResetAccount, PasswordResetLink } from '../interfaces/password-reset.interface.js';

/**
 * Implemented by the app: finds accounts by address, delivers reset links,
 * and stores new password hashes (the module ships no mailer and never reads
 * your users table). An ordinary provider of one of your modules, which
 * registers itself from its constructor:
 * `registry.registerHandler('passwordReset', this)`.
 */
export abstract class PasswordResetHandler {
  /**
   * The account whose address this is, with the address and the password
   * hash it has stored, or `null`. Called with the address trimmed,
   * lowercased and in Unicode NFC.
   */
  abstract findUser(email: string): PasswordResetAccount | null | Promise<PasswordResetAccount | null>;
  abstract send(link: PasswordResetLink): void | Promise<void>;
  /** Stores the new password's hash: from `hashPassword()` when the handler has it, else from `PasswordHasher`. */
  abstract updatePassword(userId: string, passwordHash: string): void | Promise<void>;
  /**
   * Optional: hashes the new password, for an app that stores another
   * format than `PasswordHasher`'s scrypt (argon2, bcrypt). Called with the
   * password as typed, without Unicode normalization, and only for one
   * `reset()` accepts: a string, not empty, at most 4 KiB. Returns the hash
   * to store, a non-empty string. When it throws, or returns anything else,
   * the password, the sign-ins and the link stay as they were.
   */
  hashPassword?(password: string): string | Promise<string>;
}
