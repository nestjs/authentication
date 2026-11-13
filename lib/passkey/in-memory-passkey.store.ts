import { Injectable } from '@nestjs/common';
import type {
  PasskeyChallengeRecord,
  PasskeyRecord,
  PasskeyStore,
} from '../interfaces/passkey-store.interface.js';

const MAX_PENDING = 10_000;

/**
 * Process-local store: the default when no source is registered, and a
 * test double. Drops expired challenges as new ones are saved, and holds at
 * most 10,000, dropping the oldest: anyone can ask for a challenge, so the
 * store must not grow with them.
 */
@Injectable()
export class InMemoryPasskeyStore implements PasskeyStore {
  private readonly challenges = new Map<string, PasskeyChallengeRecord>();
  private readonly passkeys = new Map<string, PasskeyRecord>();

  async savePasskeyChallenge(record: PasskeyChallengeRecord) {
    const now = record.createdAt.getTime();
    // Insertion order is expiry order (one lifetime per service): stop at the first live entry.
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt.getTime() > now) {
        break;
      }
      this.challenges.delete(id);
    }

    this.challenges.set(record.id, { ...record });
    for (const id of this.challenges.keys()) {
      if (this.challenges.size <= MAX_PENDING) {
        break;
      }
      this.challenges.delete(id); // insertion order: the oldest first
    }
  }

  async consumePasskeyChallenge(id: string) {
    const record = this.challenges.get(id);
    this.challenges.delete(id);
    return record;
  }

  async savePasskey(record: PasskeyRecord) {
    if (this.passkeys.has(record.id)) {
      throw new Error(`Passkey ${record.id} already exists`);
    }
    this.passkeys.set(record.id, { ...record });
  }

  async getPasskey(id: string) {
    const record = this.passkeys.get(id);
    return record && { ...record };
  }

  async listUserPasskeys(userId: string) {
    return [...this.passkeys.values()]
      .filter((record) => record.userId === userId)
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
      .map((record) => ({ ...record }));
  }

  async touchPasskey(id: string, counter: number, usedAt: Date) {
    const record = this.passkeys.get(id);
    if (record) {
      record.counter = counter;
      record.lastUsedAt = usedAt;
    }
  }

  async deletePasskey(id: string, userId: string) {
    return this.passkeys.get(id)?.userId === userId && this.passkeys.delete(id);
  }
}
