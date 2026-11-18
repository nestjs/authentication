export interface RefreshTokenRecord {
  /** SHA-256 of the token. */
  id: string;
  /** Every rotation stays in the family of the original sign-in. */
  familyId: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  /** The family cannot be extended past this, however often it rotates. */
  familyExpiresAt: Date;
  usedAt?: Date;
  /**
   * Claims set at sign-in (`amr`, `auth_time`, …) that every token of the
   * family carries, so access tokens minted on refresh describe the same
   * authentication: a sign-in that passed MFA stays MFA-verified. A `claims`
   * mapper passed to `refresh()` can replace them, except `amr`, `auth_time`
   * and the registered JWT claims.
   */
  claims?: Record<string, unknown>;
}

/**
 * Storage for refresh tokens. Implement it on your database or Redis, and
 * register the provider with
 * `AuthenticationStorage.registerSource({ refreshTokens: this })`.
 *
 * `markRefreshTokenUsed()` is what detects a stolen token, and must be one
 * conditional write (`UPDATE … SET used_at = ? WHERE id = ? AND used_at IS
 * NULL`), never a read followed by a write. A family's revocation must
 * cover tokens saved *after* it: a refresh that lost the race to a reuse
 * may still save its successor. Each method's comment has its rule, and
 * `authenticationStoreContract()` from `@nestjs/authentication/testing`
 * checks them.
 *
 * Optional fields come back absent (`undefined`), never `null`. Times come
 * from `TokenService`'s clock, never the store's.
 */
export interface RefreshTokenStore {
  /** The token, or `undefined`. Used and expired tokens are returned too: `TokenService` checks them. */
  getRefreshToken(id: string): Promise<RefreshTokenRecord | undefined>;
  /**
   * Saves a new token (a fresh random id: a plain insert). A good place to
   * delete tokens whose `familyExpiresAt` has passed, so the store stays
   * bounded (and with them their family's revocation, which no longer
   * matters).
   */
  saveRefreshToken(record: RefreshTokenRecord): Promise<void>;
  /**
   * Sets `usedAt = at` iff the token exists and is unused, in one
   * conditional write; `true` if this call did. Of several concurrent
   * calls, exactly one gets `true`: the others are a reuse, and revoke the
   * family.
   */
  markRefreshTokenUsed(id: string, at: Date): Promise<boolean>;
  /**
   * Revokes the family: `isRefreshTokenFamilyRevoked()` answers `true` from
   * now on, including for tokens of the family saved later. Idempotent.
   */
  revokeRefreshTokenFamily(familyId: string): Promise<void>;
  /** Whether the family was revoked (by `revokeRefreshTokenFamily()` or `revokeUserRefreshTokens()`). */
  isRefreshTokenFamilyRevoked(familyId: string): Promise<boolean>;
  /** Revokes every family the user has tokens in now. Families started later are not affected. */
  revokeUserRefreshTokens(userId: string): Promise<void>;
}
