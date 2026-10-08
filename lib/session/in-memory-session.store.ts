import { Injectable } from '@nestjs/common';
import type { SessionRecord, SessionStore } from '../interfaces/session-store.interface.js';

/**
 * Process-local store: the default when no source is registered, and a
 * test double. Sessions past their absolute expiry are dropped as new ones
 * are written, so an app that runs for months does not grow without bound.
 */
@Injectable()
export class InMemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, SessionRecord>();
  private sweepAt = 1_024;

  async getSession(id: string) {
    const record = this.sessions.get(id);
    return record && { ...record };
  }

  async createSession(record: SessionRecord) {
    // `extra` is read with a session, never stored.
    const { extra: _, ...stored } = record;
    this.sessions.set(record.id, stored);
    // The new session's own clock, so tests with a fake one agree.
    if (this.sessions.size >= this.sweepAt) {
      this.sweep(record.lastActiveAt.getTime());
    }
  }

  async touchSession(id: string, lastActiveAt: Date) {
    const record = this.sessions.get(id);
    if (record && record.lastActiveAt < lastActiveAt) {
      this.sessions.set(id, { ...record, lastActiveAt });
    }
  }

  async deleteSession(id: string) {
    return this.sessions.delete(id);
  }

  async listUserSessions(userId: string) {
    return [...this.sessions.values()].filter((s) => s.userId === userId).map((s) => ({ ...s }));
  }

  async deleteUserSessions(userId: string) {
    for (const [id, s] of this.sessions) {
      if (s.userId === userId) {
        this.sessions.delete(id);
      }
    }
  }

  private sweep(now: number) {
    for (const [id, s] of this.sessions) {
      if (s.expiresAt.getTime() <= now) {
        this.sessions.delete(id);
      }
    }
    this.sweepAt = Math.max(1_024, this.sessions.size * 2);
  }
}
