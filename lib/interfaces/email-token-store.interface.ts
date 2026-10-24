/** What a mailed token proves when it comes back. */
export type EmailTokenPurpose = 'password-reset' | 'email-verification';

/**
 * A token sent by email to prove control of an address: a password reset
 * link, or an email verification link. Stored by the SHA-256 of the token;
 * the token itself only exists in the email.
 */
export interface EmailTokenRecord {
  /** SHA-256 of the token. */
  id: string;
  purpose: EmailTokenPurpose;
  userId: string;
  /** The address the token was sent to, and the only one it works for. */
  email: string;
  /**
   * Password resets: SHA-256 of the user's password hash when the link was
   * sent, so a password change (by any route) invalidates the link.
   */
  fingerprint?: string;
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Storage for password reset and email verification tokens. Implement it
 * on your database or Redis, and register the provider with
 * `AuthenticationStorage.registerSource({ emailTokens: this })`.
 *
 * `consumeEmailToken()` must be one atomic get-and-delete
 * (`DELETE … RETURNING`, `GETDEL`), so a link works once however many
 * requests present it. Anyone can ask for a reset link, so the store must
 * stay bounded: drop expired tokens as new ones are saved, and cap the
 * rest. Each method's comment has its rule, and
 * `authenticationStoreContract()` from `@nestjs/authentication/testing`
 * checks them.
 */
export interface EmailTokenStore {
  /**
   * Saves a new token (a fresh random id: a plain insert), then keeps the
   * store bounded: deletes tokens whose `expiresAt` is at or before this
   * one's `createdAt`, and past a cap, those that expire first. The services
   * also save back a record `consumeEmailToken()` just returned, when a step
   * after it failed: its id is free again, so that is a plain insert too.
   */
  saveEmailToken(record: EmailTokenRecord): Promise<void>;
  /**
   * Removes and returns the token if it exists and was issued for
   * `purpose`, in one atomic step; `undefined` otherwise, leaving a token of
   * another purpose in place. Of several concurrent calls, exactly one gets
   * the record. Expired tokens may be returned: the services check expiry.
   */
  consumeEmailToken(id: string, purpose: EmailTokenPurpose): Promise<EmailTokenRecord | undefined>;
  /** Deletes the user's outstanding tokens for `purpose` (after a reset, the other reset links). */
  deleteUserEmailTokens(userId: string, purpose: EmailTokenPurpose): Promise<void>;
}
