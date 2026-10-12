import type { CookieAttributes } from '../session/cookies.util.js';
import type { Duration } from './duration.interface.js';

export interface MagicLink {
  email: string;
  url: string;
  expiresAt: Date;
}

/** The account behind an address, as `MagicLinkHandler.resolveUser()` returns it. */
export interface MagicLinkAccount {
  id: string;
  /**
   * The address the account has stored. The link signs the account in only
   * when it is the link's address (compared trimmed and lowercased).
   */
  email: string;
}

export interface MagicLinkOptions {
  /** Page that receives `?token=…`, e.g. `https://app.example.com/auth/magic`. */
  url: string;
  /** Lifetime of a link. Default `'15m'`. */
  ttl?: Duration;
  /**
   * Whether a link works only in the browser that requested it. Default
   * `true`: `create()` sets a transaction cookie, and `consume()` refuses a
   * link the browser holds no cookie for (`magic-link-refused`,
   * `not-this-browser`). The cookie keeps the last five links the browser
   * requested: a "resend" does not void the link before it. Without it, anyone can request a link for their
   * own address and get someone else to open it, which signs that person's
   * browser in to the attacker's account (login CSRF). `false` trades that
   * for links that work on another device than the one that asked for them
   * (requested on the laptop, opened on the phone).
   */
  bindToBrowser?: boolean;
  /**
   * Attributes of the transaction cookie, `__Host-magic_link_tx` (or
   * `magic_link_tx` when they rule the prefix out). `secure` defaults to
   * `true`; `SameSite` is always `Lax`, which lets the cookie through the
   * top-level navigation from the mail client to the page.
   */
  cookie?: CookieAttributes;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

/** The HTTP request that presents a link, as Express and Fastify provide it. */
export type MagicLinkRequest = { headers: Record<string, string | string[] | undefined> };

export interface CreatedMagicLink {
  expiresAt: Date;
  /**
   * The `Set-Cookie` value of the transaction cookie, already set on the HTTP
   * response when called from a handler; send it yourself elsewhere. Absent
   * with `bindToBrowser: false`.
   */
  cookie?: string;
}
