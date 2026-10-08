/**
 * The contract suite (`@nestjs/authentication/testing`) against stores that are wrong without any
 * concurrency: each mistake fails the case that names it, with a message that says what is wrong.
 * Also its options and how it calls `create()`.
 */
import { AssertionError } from 'node:assert';
import {
  InMemoryEmailTokenStore,
  InMemoryMagicLinkStore,
  InMemoryMfaStore,
  InMemoryOidcStateStore,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  type AuthenticationStorageSources,
  type EmailTokenPurpose,
  type MagicLinkRecord,
  type SessionRecord,
} from '../lib/index.js';
import { authenticationStoreContract, type AuthenticationStoreContractOptions } from '../lib/testing/index.js';

const inMemory = (): AuthenticationStorageSources => ({
  sessions: new InMemorySessionStore(),
  refreshTokens: new InMemoryRefreshTokenStore(),
  mfa: new InMemoryMfaStore(),
  magicLinks: new InMemoryMagicLinkStore(),
  oidcStates: new InMemoryOidcStateStore(),
  emailTokens: new InMemoryEmailTokenStore(),
});

/** Runs every case; the failed ones by name, with their assertion messages. */
async function failures(sources: () => AuthenticationStorageSources, options: AuthenticationStoreContractOptions) {
  const failed: Record<string, string> = {};
  for (const c of authenticationStoreContract(sources, options)) {
    await c.run().catch((error: Error) => {
      expect(error).toBeInstanceOf(AssertionError);
      failed[c.name] = error.message.split('\n')[0];
    });
  }
  return failed;
}

/** A SQL row mapper that turns missing columns into `null`. */
class NullingSessionStore extends InMemorySessionStore {
  override async getSession(id: string) {
    const record = await super.getSession(id);
    return (record ? { mfa: null, metadata: null, ...record } : null) as unknown as SessionRecord | undefined;
  }
}

/** `SELECT … FROM sessions JOIN users …`: reads the session's user with it, into `extra`. */
class JoiningSessionStore extends InMemorySessionStore {
  override async getSession(id: string) {
    const record = await super.getSession(id);
    return record && { ...record, extra: { user: { id: record.userId, email: `${record.userId}@example.com`, name: 'Ada', roles: [] } } };
  }
}

/** `UPDATE sessions SET last_active_at = ?` without `AND last_active_at < ?`. */
class BackwardsTouchSessionStore extends InMemorySessionStore {
  override async touchSession(id: string, lastActiveAt: Date) {
    const record = await this.getSession(id);
    if (record) {
      await this.createSession({ ...record, lastActiveAt });
    }
  }
}

/** An upsert: `INSERT … ON CONFLICT DO UPDATE`, which recreates a signed-out session. */
class UpsertTouchSessionStore extends InMemorySessionStore {
  private readonly seen = new Map<string, SessionRecord>();
  override async createSession(record: SessionRecord) {
    this.seen.set(record.id, record);
    return super.createSession(record);
  }
  override async touchSession(id: string, lastActiveAt: Date) {
    const record = (await this.getSession(id)) ?? this.seen.get(id);
    if (record && record.lastActiveAt < lastActiveAt) {
      await super.createSession({ ...record, lastActiveAt });
    }
  }
}

/** `DELETE FROM email_tokens WHERE id = ? RETURNING *`, forgetting the purpose. */
class PurposeBlindEmailTokenStore extends InMemoryEmailTokenStore {
  override async consumeEmailToken(id: string, _purpose: EmailTokenPurpose) {
    return (await super.consumeEmailToken(id, 'password-reset')) ?? super.consumeEmailToken(id, 'email-verification');
  }
}

/** A read that forgets to delete. */
class RereadableMagicLinkStore extends InMemoryMagicLinkStore {
  private readonly kept = new Map<string, MagicLinkRecord>();
  override async saveMagicLink(record: MagicLinkRecord) {
    this.kept.set(record.id, record);
    return super.saveMagicLink(record);
  }
  override async consumeMagicLink(id: string) {
    return (await super.consumeMagicLink(id)) ?? this.kept.get(id);
  }
}

describe('the contract suite catches stores that are wrong without concurrency', () => {
  it('a store that answers null for missing records and fields', async () => {
    expect(await failures(() => ({ sessions: new NullingSessionStore() }), { contracts: ['sessions'] })).toEqual({
      'sessions: round-trips every field; lists and deletes by user': 'optional fields come back absent, not null',
      'sessions: touchSession() moves lastActiveAt forward only, and never recreates a deleted session':
        'touchSession() of a deleted session must not bring it back', // `null` is not "gone"
      'sessions: createSession() prunes only sessions past their absolute expiry, however long idle':
        'a session idle for a long time, but within its absolute expiry, is kept',
    });
  });

  it('a touch that moves lastActiveAt back', async () => {
    expect(await failures(() => ({ sessions: new BackwardsTouchSessionStore() }), { contracts: ['sessions'] })).toEqual({
      'sessions: touchSession() moves lastActiveAt forward only, and never recreates a deleted session':
        'touchSession() never moves lastActiveAt back',
    });
  });

  it('a touch that brings a deleted session back', async () => {
    expect(await failures(() => ({ sessions: new UpsertTouchSessionStore() }), { contracts: ['sessions'] })).toEqual({
      'sessions: touchSession() moves lastActiveAt forward only, and never recreates a deleted session':
        'touchSession() of a deleted session must not bring it back',
    });
  });

  it('email tokens consumed for any purpose', async () => {
    expect(await failures(() => ({ emailTokens: new PurposeBlindEmailTokenStore() }), { contracts: ['emailTokens'] })).toEqual({
      'emailTokens: a token is consumed only for its purpose; deleteUserEmailTokens() is per user and purpose':
        'a token of another purpose is refused',
    });
  });

  it('magic links handed out more than once', async () => {
    expect(await failures(() => ({ magicLinks: new RereadableMagicLinkStore() }), { contracts: ['magicLinks'] })).toEqual({
      'magicLinks: hands a link out once, and drops expired ones as new ones are saved': 'a link is consumed once',
    });
  });
});

describe('authenticationStoreContract()', () => {
  it('passes a store whose getSession() sets `extra`, which is read, not stored', async () => {
    expect(await failures(() => ({ sessions: new JoiningSessionStore() }), { contracts: ['sessions'], concurrent: true })).toEqual({});
  });

  it('refuses a maxPending that is not a positive integer', () => {
    for (const maxPending of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => authenticationStoreContract(inMemory, { maxPending })).toThrow(
        `authenticationStoreContract(): maxPending must be a positive integer (got ${maxPending})`,
      );
    }
  });

  it('calls create() once per case run, not when listing the cases', async () => {
    const create = vi.fn(inMemory);
    const cases = authenticationStoreContract(create, { contracts: ['magicLinks', 'emailTokens'] });
    expect(create).not.toHaveBeenCalled();

    for (const c of cases) {
      await c.run();
    }
    expect(create).toHaveBeenCalledTimes(cases.length);
  });

  it('names every case after its contract, and adds cases for `concurrent` and `maxPending` only', () => {
    const plain = authenticationStoreContract(inMemory);
    const full = authenticationStoreContract(inMemory, { concurrent: true, maxPending: 5 });

    for (const c of full) {
      expect(c.name.startsWith(`${c.contract}: `)).toBe(true);
    }
    expect(new Set(plain.map((c) => c.contract))).toEqual(
      new Set(['sessions', 'refreshTokens', 'mfa', 'magicLinks', 'oidcStates', 'emailTokens']),
    );
    expect(full.length).toBeGreaterThan(plain.length);
    expect(plain.map((c) => c.name).every((name) => full.some((c) => c.name === name))).toBe(true);
    expect(new Set(full.map((c) => c.name)).size).toBe(full.length);
  });
});
