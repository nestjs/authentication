/**
 * `EmailVerificationService` and `PasswordResetService` built with `new`, on an injected clock:
 * link URLs, expiry boundaries, what each refusal leaves behind, purposes kept apart, and the
 * requests the module waits for on shutdown.
 */
import { ForbiddenException, Logger } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/internal';
import {
  AuthenticationEvents,
  EmailVerificationHandler,
  EmailVerificationService,
  InMemoryEmailTokenStore,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  MfaService,
  PasswordHasher,
  PasswordResetHandler,
  PasswordResetService,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationEvent,
  type EmailVerificationLink,
  type PasswordResetAccount,
  type PasswordResetLink,
} from '../lib/index.js';
import { AuthenticationScope } from '../lib/context/authentication-scope.service.js';
import { sha256 } from '../lib/utils/crypto.util.js';
import { registryWith, storageWith } from './fixtures.js';

const T0 = 1_700_000_000_000;
const tokenOf = (url: string) => new URL(url).searchParams.get('token')!;

class Mailer extends EmailVerificationHandler {
  readonly sent: EmailVerificationLink[] = [];
  readonly marked: [string, string][] = [];
  accept = true;
  send(link: EmailVerificationLink) {
    this.sent.push(link);
  }
  markVerified(userId: string, email: string) {
    this.marked.push([userId, email]);
    return this.accept;
  }
}

function verificationWith(options: { url?: string; ttl?: string } = {}) {
  let clock = T0;
  const store = new InMemoryEmailTokenStore();
  const mailer = new Mailer();
  const events = new AuthenticationEvents();
  const seen: AuthenticationEvent[] = [];
  events.events$.subscribe((event) => seen.push(event));

  const emailVerification = { url: 'https://app.test/verify-email', now: () => clock, ...options } as never;
  const service = new EmailVerificationService(
    storageWith({ emailTokens: store }),
    registryWith({ emailVerification }, { emailVerification: mailer }),
    { emailVerification },
    events,
  );
  return { service, store, mailer, seen, tick: (ms: number) => (clock += ms) };
}

describe('EmailVerificationService', () => {
  it('sends the address as the account has it, and a link that keeps the page’s own query parameters', async () => {
    const { service, mailer } = verificationWith({ url: 'https://app.test/verify?lang=pl' });
    const { expiresAt } = await service.send({ id: 'u1', email: 'Ada@Example.COM' });

    expect(expiresAt).toEqual(new Date(T0 + 86_400_000));
    expect(mailer.sent).toEqual([{ userId: 'u1', email: 'Ada@Example.COM', url: expect.any(String), expiresAt }]);
    const url = new URL(mailer.sent[0].url);
    expect(url.searchParams.get('lang')).toBe('pl');
    expect(url.searchParams.get('token')).toMatch(/^[\w-]{43}$/);
  });

  it('asks markVerified() about the address as stored, so a case-sensitive comparison matches', async () => {
    const { service, mailer } = verificationWith();
    await service.send({ id: 'u1', email: 'Ada@Example.com' });

    await expect(service.verify(tokenOf(mailer.sent[0].url))).resolves.toEqual({ userId: 'u1', email: 'Ada@Example.com' });
    expect(mailer.marked).toEqual([['u1', 'Ada@Example.com']]);
    await expect(service.send({ id: 'u2', email: ' ' })).rejects.toThrow(/the user needs an `email`/);
  });

  it('stores only the hash of the token', async () => {
    const { service, mailer, store } = verificationWith();
    await service.send({ id: 'u1', email: 'ada@example.com' });
    const token = tokenOf(mailer.sent[0].url);

    await expect(store.consumeEmailToken(token, 'email-verification')).resolves.toBeUndefined();
    await expect(store.consumeEmailToken(sha256(token), 'email-verification')).resolves.toMatchObject({ userId: 'u1' });
  });

  it('accepts a link until the millisecond before `ttl` runs out', async () => {
    const { service, mailer, tick } = verificationWith({ ttl: '10m' });
    await service.send({ id: 'u1', email: 'ada@example.com' });

    tick(599_999);
    await expect(service.verify(tokenOf(mailer.sent[0].url))).resolves.toEqual({ userId: 'u1', email: 'ada@example.com' });

    const again = verificationWith({ ttl: '10m' });
    await again.service.send({ id: 'u1', email: 'ada@example.com' });
    again.tick(600_000);
    await expect(again.service.verify(tokenOf(again.mailer.sent[0].url))).resolves.toBeNull();
    expect(again.mailer.marked).toEqual([]);
  });

  it('never looks up malformed tokens', async () => {
    const { service, store } = verificationWith();
    const consume = vi.spyOn(store, 'consumeEmailToken');
    for (const token of ['', 'short', 'A'.repeat(44), '../../etc/passwd', 42, null]) {
      await expect(service.verify(token as never)).resolves.toBeNull();
    }
    expect(consume).not.toHaveBeenCalled();
  });

  it('burns a link whose address changed, publishes nothing, and keeps the user’s other links', async () => {
    const { service, mailer, seen } = verificationWith();
    await service.send({ id: 'u1', email: 'old@example.com' });
    await service.send({ id: 'u1', email: 'new@example.com' });
    const [old, current] = mailer.sent.map((link) => tokenOf(link.url));

    mailer.accept = false;
    await expect(service.verify(old)).resolves.toBeNull();
    mailer.accept = true;
    await expect(service.verify(old)).resolves.toBeNull(); // used up
    expect(seen).toEqual([]);

    await expect(service.verify(current)).resolves.toEqual({ userId: 'u1', email: 'new@example.com' });
    expect(seen).toEqual([{ type: 'email-verified', userId: 'u1', email: 'new@example.com' }]);
  });

  it('a verified address burns the user’s other verification links, but not other users’ nor reset links', async () => {
    const { service, mailer, store } = verificationWith();
    await service.send({ id: 'u1', email: 'ada@example.com' });
    await service.send({ id: 'u1', email: 'ada@example.com' });
    await service.send({ id: 'u2', email: 'bob@example.com' });
    await store.saveEmailToken({
      id: 'reset-1',
      purpose: 'password-reset',
      userId: 'u1',
      email: 'ada@example.com',
      createdAt: new Date(T0),
      expiresAt: new Date(T0 + 60_000),
    });
    const [first, second, bobs] = mailer.sent.map((link) => tokenOf(link.url));

    await expect(service.verify(first)).resolves.not.toBeNull();
    await expect(service.verify(second)).resolves.toBeNull();
    await expect(service.verify(bobs)).resolves.toEqual({ userId: 'u2', email: 'bob@example.com' });
    await expect(store.consumeEmailToken('reset-1', 'password-reset')).resolves.toMatchObject({ userId: 'u1' });
  });

  it('never takes a password reset token as a verification link', async () => {
    const { service, store, mailer } = verificationWith();
    const token = 'R'.repeat(43);
    await store.saveEmailToken({
      id: sha256(token),
      purpose: 'password-reset',
      userId: 'u1',
      email: 'ada@example.com',
      createdAt: new Date(T0),
      expiresAt: new Date(T0 + 60_000),
    });

    await expect(service.verify(token)).resolves.toBeNull();
    expect(mailer.marked).toEqual([]);
    await expect(store.consumeEmailToken(sha256(token), 'password-reset')).resolves.toBeDefined(); // left alone
  });

  it('says how to enable the feature when it is off, and checks the url and ttl when it is created', async () => {
    const off = new EmailVerificationService(storageWith(), registryWith());
    const message =
      'EmailVerificationService: email verification is not enabled. Configure `emailVerification` in the AuthenticationModule options, ' +
      "and register an EmailVerificationHandler: `registry.registerHandler('emailVerification', this)`.";
    await expect(off.send({ id: 'u1', email: 'a@b.c' })).rejects.toThrow(message);
    await expect(off.verify('A'.repeat(43))).rejects.toThrow(message);

    expect(() => verificationWith({ url: 'app.test/verify' })).toThrow(/`emailVerification\.url` must be an absolute http\(s\) URL/);
    expect(() => verificationWith({ ttl: '1 day' })).toThrow(/Invalid duration "1 day"/);
  });
});

class Accounts extends PasswordResetHandler {
  readonly rows = new Map<string, PasswordResetAccount & { email: string }>();
  readonly sent: PasswordResetLink[] = [];
  readonly lookups: string[] = [];
  lookup?: Promise<void>;

  async findUser(email: string) {
    this.lookups.push(email);
    await this.lookup;
    const row = [...this.rows.values()].find((r) => r.email === email);
    return row ? { id: row.id, email: row.email, passwordHash: row.passwordHash } : null;
  }
  send(link: PasswordResetLink) {
    this.sent.push(link);
  }
  updatePassword(userId: string, passwordHash: string) {
    this.rows.get(userId)!.passwordHash = passwordHash;
  }
}

function resetWith({ withVerification = false, ttl }: { withVerification?: boolean; ttl?: string } = {}) {
  let clock = T0;
  const accounts = new Accounts();
  const mailer = new Mailer();
  const hasher = new PasswordHasher({ logN: 10 });
  const emailTokens = new InMemoryEmailTokenStore();
  const storage = storageWith({
    emailTokens,
    sessions: new InMemorySessionStore(),
    refreshTokens: new InMemoryRefreshTokenStore(),
  });

  const events = new AuthenticationEvents();
  const seen: AuthenticationEvent[] = [];
  events.events$.subscribe((event) => seen.push(event));

  const passwordReset = { url: 'https://app.test/reset', now: () => clock, ...(ttl && { ttl }) } as never;
  const options = { passwordReset, ...(withVerification && { emailVerification: { url: 'https://app.test/verify' } }) };
  const registry = registryWith(options, { passwordReset: accounts, ...(withVerification && { emailVerification: mailer }) });

  const sessions = new SessionService(storage, {});
  const tokens = new TokenService(storage, { accessToken: { key: 'x'.repeat(32) } });
  const scope = new AuthenticationScope();
  const signIn = new SignInService(sessions, new MfaService(storage, {}), tokens, scope, undefined, events);
  const service = new PasswordResetService(storage, registry, hasher, sessions, tokens, signIn, options, events, scope);

  class Handler {
    handle() {}
  }
  /** Runs `fn` as the handler of a POST with these headers. */
  const inRequest = <R>(headers: Record<string, string>, fn: () => Promise<R>) => {
    const context = new ExecutionContextHost([{ headers, method: 'POST' }, {}], Handler, Handler.prototype.handle);
    context.setType('http');
    return scope.run({ result: null, context }, fn);
  };

  /** Lets the work request() started in the background finish. */
  const settle = () => service.onModuleDestroy();
  const linkFor = async (email: string) => {
    service.request(email);
    await settle();
    return tokenOf(accounts.sent.at(-1)!.url);
  };

  return { service, accounts, mailer, hasher, sessions, tokens, emailTokens, seen, settle, linkFor, inRequest, tick: (ms: number) => (clock += ms) };
}

describe('PasswordResetService', () => {
  it('looks the address up trimmed and lower-cased, and ignores anything but a string', async () => {
    const { service, accounts, settle } = resetWith();
    service.request('  ADA@Example.com ');
    service.request(undefined as never);
    service.request({ email: 'ada@example.com' } as never);
    await settle();

    expect(accounts.lookups).toEqual(['ada@example.com']);
  });

  it('on shutdown, waits for the requests still looking the account up', async () => {
    const { service, accounts } = resetWith();
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    let release!: () => void;
    accounts.lookup = new Promise((resolve) => (release = resolve));

    service.request('ada@example.com');
    let destroyed = false;
    const shutdown = service.onModuleDestroy().then(() => (destroyed = true));

    await Promise.resolve();
    expect(destroyed).toBe(false);
    release();
    await shutdown;
    expect(accounts.sent).toHaveLength(1);
  });

  it('sets a first password for an account that had none', async () => {
    const { service, accounts, hasher, linkFor } = resetWith();
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: null });

    const token = await linkFor('ada@example.com');
    await expect(service.reset(token, 'first password')).resolves.toEqual({ userId: 'u1' });
    await expect(hasher.verify('first password', accounts.rows.get('u1')!.passwordHash!)).resolves.toBe(true);
  });

  it('refuses a link once its address belongs to another account', async () => {
    const { service, accounts, linkFor } = resetWith();
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h1' });
    const token = await linkFor('ada@example.com');

    accounts.rows.get('u1')!.email = 'ada@elsewhere.test';
    accounts.rows.set('u2', { id: 'u2', email: 'ada@example.com', passwordHash: 'h1' }); // same hash: only the id tells them apart

    await expect(service.reset(token, 'new password')).resolves.toBeNull();
    expect(accounts.rows.get('u2')!.passwordHash).toBe('h1');
  });

  it('accepts a link until the millisecond before `ttl` runs out', async () => {
    const early = resetWith({ ttl: '5m' });
    early.accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    const onTime = await early.linkFor('ada@example.com');
    early.tick(299_999);
    await expect(early.service.reset(onTime, 'new password')).resolves.toEqual({ userId: 'u1' });

    const late = resetWith({ ttl: '5m' });
    late.accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    const expired = await late.linkFor('ada@example.com');
    late.tick(300_000);
    await expect(late.service.reset(expired, 'new password')).resolves.toBeNull();
    expect(late.accounts.rows.get('u1')!.passwordHash).toBe('h');
  });

  it('refuses malformed tokens, and passwords the hasher would refuse, before any lookup', async () => {
    const { service, accounts, linkFor } = resetWith();
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    const token = await linkFor('ada@example.com');
    accounts.lookups.length = 0;

    await expect(service.reset(token, 12345678 as never)).resolves.toBeNull();
    await expect(service.reset(token, '')).resolves.toBeNull(); // an empty form field sets no password
    await expect(service.reset(token, 'x'.repeat(4097))).resolves.toBeNull(); // over 4 KiB: no 500, no burnt link
    await expect(service.reset(`${token}x`, 'new password')).resolves.toBeNull();
    expect(accounts.lookups).toEqual([]);
    expect(accounts.rows.get('u1')!.passwordHash).toBe('h');

    // The refusals did not burn the link.
    await expect(service.reset(token, 'new password')).resolves.toEqual({ userId: 'u1' });
  });

  it('never takes a verification link as a reset link', async () => {
    const { service, accounts, emailTokens } = resetWith();
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    const token = 'V'.repeat(43);
    await emailTokens.saveEmailToken({
      id: sha256(token),
      purpose: 'email-verification',
      userId: 'u1',
      email: 'ada@example.com',
      createdAt: new Date(T0),
      expiresAt: new Date(T0 + 60_000),
    });

    await expect(service.reset(token, 'new password')).resolves.toBeNull();
    expect(accounts.rows.get('u1')!.passwordHash).toBe('h');
    await expect(emailTokens.consumeEmailToken(sha256(token), 'email-verification')).resolves.toBeDefined(); // left alone
  });

  it('ends every session and token client, marks the address verified, and signs in only when asked', async () => {
    const { service, accounts, mailer, sessions, tokens, seen, linkFor } = resetWith({ withVerification: true });
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    const laptop = await sessions.create('u1');
    const client = await tokens.issue('u1');

    const plain = await service.reset(await linkFor('ada@example.com'), 'new password');
    expect(plain).toEqual({ userId: 'u1' });
    await expect(sessions.validate(laptop.token)).resolves.toBeNull();
    await expect(tokens.refresh(client.refreshToken)).rejects.toMatchObject({ reason: 'invalid' });
    expect(mailer.marked).toEqual([['u1', 'ada@example.com']]);

    const signedIn = await service.reset(await linkFor('ada@example.com'), 'newer password', { signIn: true });
    expect(signedIn).toEqual({ userId: 'u1', signedIn: expect.objectContaining({ cookie: expect.stringMatching(/^__Host-sid=/) }) });
    await expect(sessions.validate(signedIn!.signedIn!.token)).resolves.toMatchObject({ userId: 'u1' });

    expect(seen.map((event) => event.type)).toEqual([
      'password-reset-requested',
      'password-reset',
      'password-reset-requested',
      'password-reset',
      'sign-in',
    ]);
    expect(seen.at(-1)).toMatchObject({ type: 'sign-in', userId: 'u1', method: 'password-reset' });
  });

  describe('reset with signIn from a request of another origin', () => {
    const crossSite = { host: 'app.test', origin: 'https://evil.test', 'sec-fetch-site': 'cross-site' };
    const sameOrigin = { host: 'app.test', origin: 'https://app.test', 'sec-fetch-site': 'same-origin' };

    it('refuses before it spends the link, changes the password, ends a session or emits an event', async () => {
      const { service, accounts, hasher, sessions, seen, linkFor, inRequest } = resetWith();
      accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: await hasher.hash('old password') });
      const laptop = await sessions.create('u1');
      const token = await linkFor('ada@example.com');

      await expect(inRequest(crossSite, () => service.reset(token, 'new password', { signIn: true }))).rejects.toThrow(
        new ForbiddenException('Cross-origin sign-in refused'),
      );

      await expect(hasher.verify('old password', accounts.rows.get('u1')!.passwordHash)).resolves.toBe(true);
      await expect(hasher.verify('new password', accounts.rows.get('u1')!.passwordHash)).resolves.toBe(false);
      await expect(sessions.validate(laptop.token)).resolves.toMatchObject({ userId: 'u1' });
      expect(seen.map((event) => event.type)).toEqual(['password-reset-requested']);

      const retried = await inRequest(sameOrigin, () => service.reset(token, 'new password', { signIn: true }));
      expect(retried).toMatchObject({ userId: 'u1', signedIn: expect.anything() });
    });

    it('answers the same refusal for a token that is not valid, so it does not tell which tokens are', async () => {
      const { service, inRequest } = resetWith();

      await expect(inRequest(crossSite, () => service.reset('X'.repeat(43), 'new password', { signIn: true }))).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    });

    it('signs in a request of the app’s own origin', async () => {
      const { service, accounts, sessions, linkFor, inRequest } = resetWith();
      accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });

      const result = await inRequest(sameOrigin, async () => service.reset(await linkFor('ada@example.com'), 'new password', { signIn: true }));

      expect(result).toEqual({ userId: 'u1', signedIn: expect.objectContaining({ cookie: expect.stringMatching(/^__Host-sid=/) }) });
      await expect(sessions.validate(result!.signedIn!.token)).resolves.toMatchObject({ userId: 'u1' });
    });

    it('does not check the origin when it does not sign in, as a reset never did', async () => {
      const { service, accounts, hasher, linkFor, inRequest } = resetWith();
      accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
      const token = await linkFor('ada@example.com');

      await expect(inRequest(crossSite, () => service.reset(token, 'new password'))).resolves.toEqual({ userId: 'u1' });
      await expect(hasher.verify('new password', accounts.rows.get('u1')!.passwordHash)).resolves.toBe(true);
    });
  });

  it('mails the link to the address the account has stored, never to the one typed', async () => {
    const { service, accounts, settle } = resetWith();
    accounts.rows.set('victim', { id: 'victim', email: 'victim@example.com', passwordHash: 'h' });
    // A lookup that ignores accents, as MySQL's default collation does: `exämple.com` finds `example.com`.
    const folded = (email: string) => email.normalize('NFD').replace(/\p{M}/gu, '');
    accounts.findUser = async (email: string) => {
      const row = [...accounts.rows.values()].find((r) => folded(r.email) === folded(email));
      return row ? { id: row.id, email: row.email, passwordHash: row.passwordHash } : null;
    };

    service.request('victim@exämple.com'); // the attacker's look-alike domain
    await settle();
    expect(accounts.sent).toEqual([expect.objectContaining({ userId: 'victim', email: 'victim@example.com' })]);
  });

  it('refuses a link once the account’s stored address changed, even to one the lookup still finds', async () => {
    const { service, accounts, linkFor } = resetWith();
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    const token = await linkFor('ada@example.com');

    accounts.rows.get('u1')!.email = 'Ada@Example.com';
    // A case-insensitive lookup still finds the account: only its stored address tells.
    accounts.findUser = async (email: string) => {
      const row = [...accounts.rows.values()].find((r) => r.email.toLowerCase() === email);
      return row ? { id: row.id, email: row.email, passwordHash: row.passwordHash } : null;
    };
    await expect(service.reset(token, 'new password')).resolves.toBeNull();
    expect(accounts.rows.get('u1')!.passwordHash).toBe('h');
  });

  it('needs the stored address and password hash from findUser(): a query that leaves one out is an error', async () => {
    const { service, accounts, linkFor, settle } = resetWith();
    const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    try {
      accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
      const token = await linkFor('ada@example.com');
      const complete = accounts.findUser.bind(accounts);

      // Without `email`, nothing is sent: there is no address that is surely the account's.
      accounts.findUser = async (email: string) => ({ ...(await complete(email))!, email: undefined as never });
      service.request('ada@example.com');
      await settle();
      expect(accounts.sent).toHaveLength(1); // only the first link
      expect(logged).toHaveBeenCalledWith('A password reset request failed', expect.stringContaining('must return the account’s stored `email`'));

      // Without `passwordHash` (a column the query left out), a link would outlive a password change.
      accounts.findUser = async (email: string) => ({ ...(await complete(email))!, passwordHash: undefined as never });
      await expect(service.reset(token, 'new password')).rejects.toThrow(/must return `passwordHash`/);
      expect(accounts.rows.get('u1')!.passwordHash).toBe('h');
    } finally {
      logged.mockRestore();
    }
  });

  it('looks the account up only after request() returned, even with a handler that works synchronously', async () => {
    const { service, accounts, settle } = resetWith();
    accounts.findUser = (email: string) => {
      accounts.lookups.push(email);
      return null as never;
    };

    service.request('ada@example.com');
    await Promise.resolve(); // what an async handler around the call would still see before it answers
    expect(accounts.lookups).toEqual([]);
    await settle();
    expect(accounts.lookups).toEqual(['ada@example.com']);
  });

  it('looks up no address that no mail should go to', async () => {
    const { service, accounts, settle } = resetWith();
    for (const email of ['ada@example.com\r\nBcc: everyone@example.com', 'no-at-sign', `${'a'.repeat(243)}@example.com`]) {
      service.request(email);
    }
    await settle();
    expect(accounts.lookups).toEqual([]);
  });

  it('revokes sign-ins before the new password is stored, and again after it', async () => {
    const { service, accounts, sessions, linkFor } = resetWith();
    accounts.rows.set('u1', { id: 'u1', email: 'ada@example.com', passwordHash: 'h' });
    const before = await sessions.create('u1');

    // A store that fails the write: the old password stays, and so does no session made with it.
    const store = accounts.updatePassword.bind(accounts);
    accounts.updatePassword = () => {
      throw new Error('database down');
    };
    await expect(service.reset(await linkFor('ada@example.com'), 'new password')).rejects.toThrow('database down');
    await expect(sessions.validate(before.token)).resolves.toBeNull();

    // A sign-in with the old password that lands while the new one is written is revoked too.
    let during: { token: string } | undefined;
    accounts.updatePassword = async (userId: string, hash: string) => {
      during = await sessions.create(userId);
      store(userId, hash);
    };
    await expect(service.reset(await linkFor('ada@example.com'), 'new password')).resolves.toEqual({ userId: 'u1' });
    await expect(sessions.validate(during!.token)).resolves.toBeNull();
  });

  it('says how to enable the feature when it is off: request() throws at once, not in the background', async () => {
    const storage = storageWith();
    const sessions = new SessionService(storage, {});
    const tokens = new TokenService(storage, {});
    const signIn = new SignInService(sessions, new MfaService(storage, {}), tokens);
    const off = new PasswordResetService(storage, registryWith(), new PasswordHasher({ logN: 10 }), sessions, tokens, signIn);

    expect(() => off.request('ada@example.com')).toThrow(/^PasswordResetService: password reset is not enabled\. /);
    await expect(off.reset('A'.repeat(43), 'pw')).rejects.toThrow(/password reset is not enabled/);
    await expect(off.onModuleDestroy()).resolves.toBeUndefined();
  });
});
