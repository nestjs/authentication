import { Injectable } from '@nestjs/common';
import {
  AuthenticationStorage,
  type EmailTokenPurpose,
  type EmailTokenRecord,
  type EmailTokenStore,
  type MagicLinkRecord,
  type MagicLinkStore,
  type MfaStore,
  type OidcStateStore,
  type OidcTransaction,
  type RefreshTokenRecord,
  type RefreshTokenStore,
  type SessionRecord,
  type SessionStore,
  type TotpRecord,
} from '../../../lib/index.js';
import { InjectDrizzle } from '@nestjs/drizzle';
import { and, desc, eq, gt, inArray, isNull, lt, lte, or, sql, type SQL } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  emailTokens,
  magicLinks,
  mfaAuthenticators,
  mfaFailures,
  mfaRecoveryCodes,
  oidcLogins,
  refreshTokens,
  sessions,
} from './schema.js';

/**
 * Keeps sessions, refresh tokens, authenticators and pending links in
 * PostgreSQL, through Drizzle. Every method that decides whether something
 * works once is a single conditional statement, so the guarantees hold with
 * any number of API instances.
 */
@Injectable()
export class DrizzleAuthenticationStore
  implements SessionStore, RefreshTokenStore, MfaStore, MagicLinkStore, OidcStateStore, EmailTokenStore
{
  /** Pending links and logins kept per table: anyone can create them. */
  protected readonly maxPending: number = 100_000;

  constructor(
    @InjectDrizzle() private readonly db: NodePgDatabase,
    storage: AuthenticationStorage,
  ) {
    storage.registerSource({
      sessions: this,
      refreshTokens: this,
      mfa: this,
      magicLinks: this,
      oidcStates: this,
      emailTokens: this,
    });
  }

  // Sessions

  async getSession(id: string): Promise<SessionRecord | undefined> {
    const [row] = await this.db.select().from(sessions).where(eq(sessions.id, id));
    return row && withoutNulls(row);
  }

  async createSession(record: SessionRecord): Promise<void> {
    await this.db.insert(sessions).values(record);
    await this.db.delete(sessions).where(lte(sessions.expiresAt, record.createdAt));
  }

  async touchSession(id: string, lastActiveAt: Date): Promise<void> {
    // Conditional: a session deleted by a sign-out stays deleted.
    await this.db
      .update(sessions)
      .set({ lastActiveAt })
      .where(and(eq(sessions.id, id), lt(sessions.lastActiveAt, lastActiveAt)));
  }

  async deleteSession(id: string): Promise<boolean> {
    const deleted = await this.db.delete(sessions).where(eq(sessions.id, id)).returning({ id: sessions.id });
    return deleted.length > 0;
  }

  async listUserSessions(userId: string): Promise<SessionRecord[]> {
    const rows = await this.db.select().from(sessions).where(eq(sessions.userId, userId));
    return rows.map(withoutNulls);
  }

  async deleteUserSessions(userId: string): Promise<void> {
    await this.db.delete(sessions).where(eq(sessions.userId, userId));
  }

  // Refresh tokens

  async getRefreshToken(id: string): Promise<RefreshTokenRecord | undefined> {
    const [row] = await this.db.select().from(refreshTokens).where(eq(refreshTokens.id, id));
    if (!row) return undefined;
    const { revoked: _, ...token } = row;
    return withoutNulls(token);
  }

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    await this.db.insert(refreshTokens).values(record);
    await this.db.delete(refreshTokens).where(lte(refreshTokens.familyExpiresAt, record.createdAt));
  }

  async markRefreshTokenUsed(id: string, at: Date): Promise<boolean> {
    // Conditional: of two refreshes with the same token, one updates the row.
    const updated = await this.db
      .update(refreshTokens)
      .set({ usedAt: at })
      .where(and(eq(refreshTokens.id, id), isNull(refreshTokens.usedAt)))
      .returning({ id: refreshTokens.id });
    return updated.length === 1;
  }

  async revokeRefreshTokenFamily(familyId: string): Promise<void> {
    await this.revokeRefreshTokens(eq(refreshTokens.familyId, familyId));
  }

  async isRefreshTokenFamilyRevoked(familyId: string): Promise<boolean> {
    const revoked = await this.db
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(and(eq(refreshTokens.familyId, familyId), eq(refreshTokens.revoked, true)))
      .limit(1);
    return revoked.length > 0;
  }

  async revokeUserRefreshTokens(userId: string): Promise<void> {
    await this.revokeRefreshTokens(eq(refreshTokens.userId, userId));
  }

  /**
   * Locks the rows in id order before updating them. Parallel refreshes of a reused token each
   * revoke the family, and two multi-row UPDATEs that lock the same rows in different orders
   * deadlock: the loser would answer with a 500 instead of a 401.
   */
  private async revokeRefreshTokens(rows: SQL): Promise<void> {
    const locked = this.db.select({ id: refreshTokens.id }).from(refreshTokens).where(rows).orderBy(refreshTokens.id).for('update');
    await this.db.update(refreshTokens).set({ revoked: true }).where(inArray(refreshTokens.id, locked));
  }

  // Authenticators, recovery codes and failed attempts

  async getTotp(userId: string): Promise<TotpRecord | undefined> {
    const [row] = await this.db.select().from(mfaAuthenticators).where(eq(mfaAuthenticators.userId, userId));
    if (!row) return undefined;
    const { userId: _, ...totp } = row;
    return withoutNulls(totp);
  }

  async saveTotp(userId: string, record: TotpRecord | null): Promise<void> {
    if (!record) {
      await this.db.delete(mfaAuthenticators).where(eq(mfaAuthenticators.userId, userId));
      return;
    }
    const values = { secret: record.secret, confirmed: record.confirmed, pendingSecret: record.pendingSecret ?? null };
    await this.db
      .insert(mfaAuthenticators)
      .values({ userId, ...values, lastUsedStep: record.lastUsedStep })
      .onConflictDoUpdate({
        target: mfaAuthenticators.userId,
        // Never lower the claimed step: the record may have been read before a claim.
        set: { ...values, lastUsedStep: sql`greatest(${mfaAuthenticators.lastUsedStep}, excluded.last_used_step)` },
      });
  }

  async claimTotpStep(userId: string, step: number): Promise<boolean> {
    // Conditional: a code's time step is accepted once.
    const claimed = await this.db
      .update(mfaAuthenticators)
      .set({ lastUsedStep: step })
      .where(
        and(
          eq(mfaAuthenticators.userId, userId),
          or(isNull(mfaAuthenticators.lastUsedStep), lt(mfaAuthenticators.lastUsedStep, step)),
        ),
      )
      .returning({ userId: mfaAuthenticators.userId });
    return claimed.length === 1;
  }

  async saveRecoveryCodes(userId: string, hashes: string[]): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, userId));
      if (hashes.length > 0) {
        await tx.insert(mfaRecoveryCodes).values([...new Set(hashes)].map((codeHash) => ({ userId, codeHash })));
      }
    });
  }

  async consumeRecoveryCode(userId: string, hash: string): Promise<boolean> {
    // Conditional: of two requests with the same code, one deletes the row.
    const consumed = await this.db
      .delete(mfaRecoveryCodes)
      .where(and(eq(mfaRecoveryCodes.userId, userId), eq(mfaRecoveryCodes.codeHash, hash)))
      .returning({ userId: mfaRecoveryCodes.userId });
    return consumed.length === 1;
  }

  countRecoveryCodes(userId: string): Promise<number> {
    return this.db.$count(mfaRecoveryCodes, eq(mfaRecoveryCodes.userId, userId));
  }

  async recordMfaFailure(userId: string, windowMs: number, now: number): Promise<number> {
    // Insert, then count, each committed on its own (no transaction): every attempt
    // counts itself and all those recorded before it.
    await this.db.insert(mfaFailures).values({ userId, failedAt: new Date(now) });
    const failures = await this.countMfaFailures(userId, windowMs, now);
    await this.db.delete(mfaFailures).where(lte(mfaFailures.failedAt, new Date(now - windowMs)));
    return failures;
  }

  countMfaFailures(userId: string, windowMs: number, now: number): Promise<number> {
    return this.db.$count(
      mfaFailures,
      and(eq(mfaFailures.userId, userId), gt(mfaFailures.failedAt, new Date(now - windowMs))),
    );
  }

  async clearMfaFailures(userId: string): Promise<void> {
    await this.db.delete(mfaFailures).where(eq(mfaFailures.userId, userId));
  }

  // Magic links

  async saveMagicLink(record: MagicLinkRecord): Promise<void> {
    await this.db.insert(magicLinks).values(record);
    await this.trim(magicLinks, record.createdAt);
  }

  async consumeMagicLink(id: string): Promise<MagicLinkRecord | undefined> {
    // DELETE … RETURNING: of two requests with the same link, one gets the row.
    const [row] = await this.db.delete(magicLinks).where(eq(magicLinks.id, id)).returning();
    return row && withoutNulls(row);
  }

  // Sign-ins with Google in progress

  async saveOidcState({ link, ...login }: OidcTransaction): Promise<void> {
    await this.db.insert(oidcLogins).values({ ...login, linkUserId: link?.userId, linkSessionId: link?.sessionId });
    await this.trim(oidcLogins, login.createdAt);
  }

  async consumeOidcState(state: string): Promise<OidcTransaction | undefined> {
    const [row] = await this.db.delete(oidcLogins).where(eq(oidcLogins.state, state)).returning();
    if (!row) return undefined;
    const { linkUserId, linkSessionId, ...login } = withoutNulls(row);
    return linkUserId && linkSessionId ? { ...login, link: { userId: linkUserId, sessionId: linkSessionId } } : login;
  }

  // Password reset and email verification links

  async saveEmailToken(record: EmailTokenRecord): Promise<void> {
    await this.db.insert(emailTokens).values(record);
    await this.trim(emailTokens, record.createdAt);
  }

  async consumeEmailToken(id: string, purpose: EmailTokenPurpose): Promise<EmailTokenRecord | undefined> {
    const [row] = await this.db
      .delete(emailTokens)
      .where(and(eq(emailTokens.id, id), eq(emailTokens.purpose, purpose)))
      .returning();
    return row && withoutNulls(row);
  }

  async deleteUserEmailTokens(userId: string, purpose: EmailTokenPurpose): Promise<void> {
    await this.db.delete(emailTokens).where(and(eq(emailTokens.userId, userId), eq(emailTokens.purpose, purpose)));
  }

  /** Deletes what expired, and past `maxPending`, what expires first. */
  private async trim(table: typeof magicLinks | typeof oidcLogins | typeof emailTokens, now: Date) {
    await this.db.delete(table).where(lte(table.expiresAt, now));
    const [cutoff] = await this.db
      .select({ expiresAt: table.expiresAt })
      .from(table)
      .orderBy(desc(table.expiresAt))
      .limit(1)
      .offset(this.maxPending);
    if (cutoff) await this.db.delete(table).where(lte(table.expiresAt, cutoff.expiresAt));
  }
}

/** A row without its NULL columns: the package's records leave optional fields out. */
type WithoutNulls<T> = { [K in keyof T as null extends T[K] ? never : K]: T[K] } & {
  [K in keyof T as null extends T[K] ? K : never]?: Exclude<T[K], null>;
};

function withoutNulls<T extends object>(row: T): WithoutNulls<T> {
  return Object.fromEntries(Object.entries(row).filter(([, value]) => value !== null)) as WithoutNulls<T>;
}
