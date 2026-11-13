export type PasskeyAlgorithm = 'ES256' | 'RS256' | 'EdDSA';

export interface PasskeyRecord {
  /** The credential id the authenticator chose, base64url: unique across users. */
  id: string;
  userId: string;
  /** The public key as SPKI DER, base64url. */
  publicKey: string;
  algorithm: PasskeyAlgorithm;
  /**
   * The signature counter of the last assertion. Synced passkeys (iCloud
   * Keychain, Google Password Manager) always report 0, and so keep it 0.
   */
  counter: number;
  /** What the browser reported at registration (`usb`, `internal`, `hybrid`…), for `allowCredentials`. */
  transports?: string[];
  createdAt: Date;
  lastUsedAt?: Date;
}

/** A challenge handed to a browser and not yet answered. */
export interface PasskeyChallengeRecord {
  /** SHA-256 of the challenge, base64url. */
  id: string;
  type: 'registration' | 'authentication';
  /** The user a registration is for, or an authentication was restricted to. */
  userId?: string;
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Storage for passkeys and the challenges in flight. Implement it on your
 * database or Redis, and register the provider with
 * `AuthenticationStorage.registerSource({ passkeys: this })`.
 *
 * `consumePasskeyChallenge()` must be one atomic get-and-delete
 * (`DELETE … RETURNING`, `GETDEL`): it is what stops two concurrent
 * assertions from both passing. Anyone can ask for a challenge, so the
 * store must stay bounded: drop expired challenges as new ones are saved,
 * and cap the rest.
 */
export interface PasskeyStore {
  /**
   * Saves a new challenge (a fresh random id: a plain insert), then keeps
   * the store bounded: deletes challenges whose `expiresAt` is at or before
   * this one's `createdAt`, and past a cap, those that expire first.
   */
  savePasskeyChallenge(record: PasskeyChallengeRecord): Promise<void>;
  /**
   * Removes and returns the challenge, in one atomic step; `undefined` if
   * there is none. Of several concurrent calls, exactly one gets the
   * record. Expired challenges may be returned: `PasskeyService` checks expiry.
   */
  consumePasskeyChallenge(
    id: string,
  ): Promise<PasskeyChallengeRecord | undefined>;
  /** Saves a new passkey. Rejects when its id is taken. */
  savePasskey(record: PasskeyRecord): Promise<void>;
  getPasskey(id: string): Promise<PasskeyRecord | undefined>;
  /** The user's passkeys, oldest first. */
  listUserPasskeys(userId: string): Promise<PasskeyRecord[]>;
  /** Sets the counter and `lastUsedAt` after an assertion. */
  touchPasskey(id: string, counter: number, usedAt: Date): Promise<void>;
  /** Deletes the passkey if it is this user's; `false` if there is none. */
  deletePasskey(id: string, userId: string): Promise<boolean>;
}
