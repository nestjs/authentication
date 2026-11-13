/**
 * The contract suite (`@nestjs/authentication/testing`) on the in-memory stores, and on
 * deliberately naive stores that read and then write where the contract asks for one conditional
 * write: the concurrency cases must catch every one of them.
 */
import { setImmediate as tick } from 'node:timers/promises';
import { describe, expect, it } from 'vitest';
import {
  InMemoryEmailTokenStore,
  InMemoryMagicLinkStore,
  InMemoryMfaStore,
  InMemoryOidcStateStore,
  InMemoryPasskeyStore,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  type AuthenticationStorageContract,
  type AuthenticationStorageSources,
  type EmailTokenPurpose,
  type EmailTokenRecord,
  type EmailTokenStore,
  type MagicLinkRecord,
  type MagicLinkStore,
  type OidcStateStore,
  type PasskeyChallengeRecord,
  type PasskeyStore,
  type RefreshTokenRecord,
} from '../lib/index.js';
import type { OidcTransaction } from '../lib/interfaces/oidc.interface.js';
import { authenticationStoreContract } from '../lib/testing/index.js';

const inMemory = (): AuthenticationStorageSources => ({
  sessions: new InMemorySessionStore(),
  refreshTokens: new InMemoryRefreshTokenStore(),
  mfa: new InMemoryMfaStore(),
  magicLinks: new InMemoryMagicLinkStore(),
  oidcStates: new InMemoryOidcStateStore(),
  passkeys: new InMemoryPasskeyStore(),
  emailTokens: new InMemoryEmailTokenStore(),
});

/** Every contract, passkeys included: they are not in the suite's default run. */
const ALL: AuthenticationStorageContract[] = ['sessions', 'refreshTokens', 'mfa', 'magicLinks', 'oidcStates', 'passkeys', 'emailTokens'];

describe('the in-memory stores pass the contract suite', () => {
  for (const c of authenticationStoreContract(inMemory, { concurrent: true, maxPending: 10_000, contracts: ALL })) {
    it(c.name, c.run);
  }
});

// ---------------------------------------------------------------- naive stores

/** Read, then write the whole record back: `repository.save(entity)`. */
class ReadThenWriteSessionStore extends InMemorySessionStore {
  override async touchSession(id: string, lastActiveAt: Date) {
    const record = await this.getSession(id);
    await tick();
    if (record && record.lastActiveAt < lastActiveAt) {
      await this.createSession({ ...record, lastActiveAt });
    }
  }

  override async deleteSession(id: string) {
    const found = (await this.getSession(id)) !== undefined;
    await tick();
    await super.deleteSession(id);
    return found;
  }
}

class ReadThenWriteRefreshTokenStore extends InMemoryRefreshTokenStore {
  override async markRefreshTokenUsed(id: string, at: Date) {
    const record = await this.getRefreshToken(id);
    await tick();
    if (!record || record.usedAt) {
      return false;
    }
    await this.saveRefreshToken({ ...record, usedAt: at } satisfies RefreshTokenRecord);
    return true;
  }
}

class ReadThenWriteMfaStore extends InMemoryMfaStore {
  private readonly codeSets = new Map<string, Set<string>>();

  override async claimTotpStep(userId: string, step: number) {
    const record = await this.getTotp(userId);
    await tick();
    if (!record || (record.lastUsedStep !== undefined && step <= record.lastUsedStep)) {
      return false;
    }
    await this.saveTotp(userId, { ...record, lastUsedStep: step });
    return true;
  }
  override async saveRecoveryCodes(userId: string, hashes: string[]) {
    this.codeSets.set(userId, new Set(hashes));
  }
  override async countRecoveryCodes(userId: string) {
    return this.codeSets.get(userId)?.size ?? 0;
  }
  override async consumeRecoveryCode(userId: string, hash: string) {
    const present = this.codeSets.get(userId)?.has(hash) ?? false;
    await tick();
    if (present) {
      this.codeSets.get(userId)?.delete(hash);
    }
    return present;
  }
  /** Counts, then records: parallel attempts all see the same low count. */
  override async recordMfaFailure(userId: string, windowMs: number, now: number) {
    const before = await this.countMfaFailures(userId, windowMs, now);
    await tick();
    await super.recordMfaFailure(userId, windowMs, now);
    return before + 1;
  }
}

/** A pending store whose consume is a read, then a delete, returning what it read. */
class ReadThenDelete<T> {
  protected readonly entries = new Map<string, T>();
  protected async take(key: string): Promise<T | undefined> {
    const entry = this.entries.get(key);
    await tick();
    this.entries.delete(key);
    return entry;
  }
  protected put(key: string, entry: T, now: number, expiresAt: (entry: T) => number) {
    for (const [k, e] of this.entries) {
      if (expiresAt(e) <= now) {
        this.entries.delete(k);
      }
    }
    this.entries.set(key, entry);
  }
}

class ReadThenDeleteMagicLinkStore extends ReadThenDelete<MagicLinkRecord> implements MagicLinkStore {
  async saveMagicLink(record: MagicLinkRecord) {
    this.put(record.id, { ...record }, record.createdAt.getTime(), (r) => r.expiresAt.getTime());
  }
  consumeMagicLink(id: string) {
    return this.take(id);
  }
}

class ReadThenDeleteOidcStateStore extends ReadThenDelete<OidcTransaction> implements OidcStateStore {
  async saveOidcState(transaction: OidcTransaction) {
    this.put(transaction.state, { ...transaction }, transaction.createdAt.getTime(), (t) => t.expiresAt.getTime());
  }
  consumeOidcState(state: string) {
    return this.take(state);
  }
}

/** Only the challenge consume is naive: the passkey calls are the in-memory store's. */
class ReadThenDeletePasskeyStore extends ReadThenDelete<PasskeyChallengeRecord> implements PasskeyStore {
  private readonly passkeys = new InMemoryPasskeyStore();
  async savePasskeyChallenge(record: PasskeyChallengeRecord) {
    this.put(record.id, { ...record }, record.createdAt.getTime(), (r) => r.expiresAt.getTime());
  }
  consumePasskeyChallenge(id: string) {
    return this.take(id);
  }
  savePasskey: PasskeyStore['savePasskey'] = (record) => this.passkeys.savePasskey(record);
  getPasskey: PasskeyStore['getPasskey'] = (id) => this.passkeys.getPasskey(id);
  listUserPasskeys: PasskeyStore['listUserPasskeys'] = (userId) => this.passkeys.listUserPasskeys(userId);
  touchPasskey: PasskeyStore['touchPasskey'] = (id, counter, usedAt) => this.passkeys.touchPasskey(id, counter, usedAt);
  deletePasskey: PasskeyStore['deletePasskey'] = (id, userId) => this.passkeys.deletePasskey(id, userId);
}

class ReadThenDeleteEmailTokenStore extends ReadThenDelete<EmailTokenRecord> implements EmailTokenStore {
  async saveEmailToken(record: EmailTokenRecord) {
    this.put(record.id, { ...record }, record.createdAt.getTime(), (r) => r.expiresAt.getTime());
  }
  async consumeEmailToken(id: string, purpose: EmailTokenPurpose) {
    if (this.entries.get(id)?.purpose !== purpose) {
      return undefined;
    }
    return this.take(id);
  }
  async deleteUserEmailTokens(userId: string, purpose: EmailTokenPurpose) {
    for (const [id, token] of this.entries) {
      if (token.userId === userId && token.purpose === purpose) {
        this.entries.delete(id);
      }
    }
  }
}

const naive = (): AuthenticationStorageSources => ({
  sessions: new ReadThenWriteSessionStore(),
  refreshTokens: new ReadThenWriteRefreshTokenStore(),
  mfa: new ReadThenWriteMfaStore(),
  magicLinks: new ReadThenDeleteMagicLinkStore(),
  oidcStates: new ReadThenDeleteOidcStateStore(),
  passkeys: new ReadThenDeletePasskeyStore(),
  emailTokens: new ReadThenDeleteEmailTokenStore(),
});

/** Runs every case, and returns the names of those that failed. */
async function failures(cases: ReturnType<typeof authenticationStoreContract>): Promise<string[]> {
  const failed: string[] = [];
  for (const c of cases) {
    await c.run().catch(() => failed.push(c.name));
  }
  return failed;
}

describe('the contract suite catches stores that read, then write', () => {
  it('passes them without `concurrent`: every sequential case holds', async () => {
    expect(await failures(authenticationStoreContract(naive, { contracts: ALL }))).toEqual([]);
  });

  it('fails each of them on its concurrency cases, and only those', async () => {
    const failed = await failures(authenticationStoreContract(naive, { concurrent: true, contracts: ALL }));
    expect(failed.sort()).toEqual(
      [
        'sessions: a request racing a sign-out or a rotation never brings the session back (SessionService)',
        'sessions: of concurrent deletes of one session, exactly one resolves true (what keeps a rotation from outliving a revocation)',
        'sessions: a rotation racing a sign-out leaves no session, and concurrent rotations leave one (SessionService)',
        'refreshTokens: markRefreshTokenUsed() succeeds once under concurrency',
        'refreshTokens: concurrent refreshes of one token revoke the family (TokenService)',
        'mfa: claimTotpStep() succeeds once under concurrency',
        'mfa: consumeRecoveryCode() succeeds once under concurrency',
        'mfa: parallel recordMfaFailure() calls never share a low count',
        'mfa: a burst of parallel guesses gets maxAttempts checks, not one per request (MfaService)',
        'magicLinks: hands a link out once under concurrency',
        'oidcStates: hands a login out once under concurrency',
        'passkeys: hands a challenge out once under concurrency',
        'emailTokens: hands a token out once under concurrency',
        'emailTokens: password reset and verification links work once under concurrency (the services)',
      ].sort(),
    );
  });

  it('checks the pending cap only when told the store has one', async () => {
    const names = authenticationStoreContract(inMemory).map((c) => c.name);
    expect(names.filter((name) => name.includes('maxPending'))).toEqual([]);

    const capped = authenticationStoreContract(inMemory, { maxPending: 3 }).map((c) => c.name);
    expect(capped.filter((name) => name.includes('maxPending'))).toHaveLength(3);

    // The in-memory stores keep 10,000: a cap of 3 is not theirs.
    const cap = authenticationStoreContract(inMemory, { maxPending: 3, contracts: ['magicLinks'] }).find((c) => c.name.includes('maxPending'))!;
    await expect(cap.run()).rejects.toThrow('the link that expires first is dropped');
  });

  it('runs only the requested contracts, and says when create() lacks one', async () => {
    const cases = authenticationStoreContract(async () => ({ sessions: new InMemorySessionStore() }), { contracts: ['sessions'] });
    expect(new Set(cases.map((c) => c.contract))).toEqual(new Set(['sessions']));

    const [first] = authenticationStoreContract(async () => ({ sessions: new InMemorySessionStore() }), { contracts: ['mfa'] });
    await expect(first.run()).rejects.toThrow('create() returned no `mfa` store');

    expect(() => authenticationStoreContract(inMemory, { contracts: ['session' as never] })).toThrow('unknown contract `session`');
  });
});
