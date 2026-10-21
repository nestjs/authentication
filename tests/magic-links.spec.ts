/**
 * `MagicLinkService` inside an HTTP exchange, without a server: the transaction cookie it sets
 * and clears on the response, its attributes, and what each outcome of `consume()` leaves behind.
 */
import { HttpAdapterHost } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/internal';
import {
  AuthenticationEvents,
  InMemoryMagicLinkStore,
  MagicLinkError,
  MagicLinkHandler,
  MagicLinkService,
  MfaService,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationEvent,
  type MagicLink,
  type MagicLinkOptions,
} from '../lib/index.js';
import { ForbiddenException } from '@nestjs/common';
import { AuthenticationScope } from '../lib/context/authentication-scope.service.js';
import { sha256 } from '../lib/utils/crypto.util.js';
import { registryWith, storageWith } from './fixtures.js';

class Mailer extends MagicLinkHandler {
  readonly sent: MagicLink[] = [];
  readonly known = new Map([['ada@example.com', { id: 'u1', email: 'ada@example.com' }]]);
  send(link: MagicLink) {
    this.sent.push(link);
  }
  resolveUser(email: string) {
    return this.known.get(email) ?? null;
  }
}

function setup(magicLink: Partial<MagicLinkOptions> = {}) {
  let clock = 1_700_000_000_000;
  const links = new InMemoryMagicLinkStore();
  const storage = storageWith({ magicLinks: links });
  const mailer = new Mailer();
  const events = new AuthenticationEvents();
  const seen: AuthenticationEvent[] = [];
  events.events$.subscribe((event) => seen.push(event));

  const scope = new AuthenticationScope();
  const adapterHost = new HttpAdapterHost();
  adapterHost.httpAdapter = {
    appendHeader: (response: { cookies: string[] }, _name: string, value: string) => response.cookies.push(value),
  } as never;

  const sessions = new SessionService(storage, { session: { cookie: { secure: false } } });
  const signIn = new SignInService(sessions, new MfaService(storage, {}), new TokenService(storage, {}), scope, adapterHost, events);
  const options = { magicLink: { url: 'https://app.test/magic', ttl: '10m' as const, now: () => clock, ...magicLink } };
  const service = new MagicLinkService(storage, registryWith(options, { magicLink: mailer }), signIn, options, scope, adapterHost, events);

  class Handler {
    handle() {}
  }
  /** Runs `fn` as the handler of a POST with these headers; the cookies it set come back. */
  const inRequest = async <R>(headers: Record<string, string>, fn: () => Promise<R>) => {
    const response = { cookies: [] as string[] };
    const context = new ExecutionContextHost([{ headers, method: 'POST' }, response], Handler, Handler.prototype.handle);
    context.setType('http');
    const result: { value?: R; error?: unknown } = await scope.run({ result: null, context }, fn).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    return { ...result, cookies: response.cookies };
  };
  const tokenOf = (link: MagicLink) => new URL(link.url).searchParams.get('token')!;
  const cookieHeader = (setCookie: string) => ({ cookie: setCookie.split(';')[0] });

  return { service, links, mailer, seen, inRequest, tokenOf, cookieHeader, tick: (ms: number) => (clock += ms) };
}

describe('MagicLinkService in an HTTP exchange', () => {
  it('sets the transaction cookie on the response that requested the link, for the link’s lifetime', async () => {
    const { service, inRequest, mailer } = setup();
    const created = await inRequest({}, () => service.create('  ADA@example.com '));

    expect(created.cookies).toEqual([expect.stringMatching(/^__Host-magic_link_tx=[\w-]{12}\.[\w-]{43}; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/)]);
    expect(created.value).toEqual({ expiresAt: mailer.sent[0].expiresAt, cookie: created.cookies[0] });
    expect(mailer.sent[0].email).toBe('ada@example.com');
  });

  it('keeps the transaction cookie SameSite=Lax whatever the options say: the link is opened from a mail client', async () => {
    const { service, inRequest } = setup({ cookie: { sameSite: 'strict', domain: 'app.test' } });
    const { cookies } = await inRequest({}, () => service.create('ada@example.com'));
    expect(cookies[0]).toMatch(/^magic_link_tx=[\w-]{12}\.[\w-]{43}; Max-Age=600; Path=\/; Domain=app\.test; HttpOnly; Secure; SameSite=Lax$/);
  });

  it('signs in the browser that requested the link, clearing its transaction cookie and setting the session', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, seen } = setup();
    const created = await inRequest({}, () => service.create('ada@example.com', { redirectTo: '/orders' }));

    const consumed = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(consumed.value).toMatchObject({ session: { userId: 'u1' }, redirectTo: '/orders' });
    expect(consumed.cookies).toEqual([
      expect.stringMatching(/^__Host-magic_link_tx=; Max-Age=0; /),
      expect.stringMatching(/^sid=[\w-]{43}; /),
    ]);
    expect(seen).toEqual([expect.objectContaining({ type: 'sign-in', userId: 'u1', method: 'magic-link' })]);
  });

  it('refuses another browser before any lookup, and leaves both its cookie and the link alone', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, links, seen } = setup();
    const mine = await inRequest({}, () => service.create('ada@example.com'));
    const other = await inRequest({}, () => service.create('ada@example.com'));
    const consume = vi.spyOn(links, 'consumeMagicLink');

    const refused = await inRequest(cookieHeader(other.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(refused.error).toBeInstanceOf(MagicLinkError);
    expect(refused.cookies).toEqual([]);
    expect(consume).not.toHaveBeenCalled();
    expect(seen).toEqual([{ type: 'magic-link-refused', reason: 'not-this-browser' }]);

    const opened = await inRequest(cookieHeader(mine.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(opened.value).toMatchObject({ session: { userId: 'u1' } });
  });

  it('keeps a link usable in its browser after that browser requests another, and settles each on its own', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader } = setup();
    const first = await inRequest({}, () => service.create('ada@example.com'));
    const second = await inRequest(cookieHeader(first.cookies[0]), () => service.create('ada@example.com'));
    const [older, newer] = mailer.sent.map(tokenOf);
    expect(second.cookies).toEqual([expect.stringMatching(/^__Host-magic_link_tx=[\w-]{12}\.[\w-]{43}~[\w-]{12}\.[\w-]{43}; Max-Age=600; /)]);
    // The newest link first, then the one before.
    expect(second.cookies[0]).toContain(`~${first.cookies[0].split(';')[0].slice('__Host-magic_link_tx='.length)};`);

    const openedOlder = await inRequest(cookieHeader(second.cookies[0]), () => service.consume(older));
    expect(openedOlder.value).toMatchObject({ session: { userId: 'u1' } });
    // Only the older link's secret goes: the cookie keeps the newer one, which opens next.
    const left = openedOlder.cookies[0];
    expect(left).toMatch(/^__Host-magic_link_tx=[\w-]{12}\.[\w-]{43}; Max-Age=600; /);
    expect(second.cookies[0].startsWith(left.split(';')[0])).toBe(true);

    const openedNewer = await inRequest(cookieHeader(left), () => service.consume(newer));
    expect(openedNewer.value).toMatchObject({ session: { userId: 'u1' } });
    expect(openedNewer.cookies[0]).toMatch(/^__Host-magic_link_tx=; Max-Age=0; /);
  });

  it('holds the last five links a browser requested, and refuses the ones before as another browser’s', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, seen } = setup();
    let headers: Record<string, string> = {};
    const pairs: string[] = [];
    for (let i = 0; i < 6; i++) {
      const created = await inRequest(headers, () => service.create('ada@example.com'));
      headers = cookieHeader(created.cookies[0]);
      pairs.push(headers.cookie.slice('__Host-magic_link_tx='.length).split('~')[0]);
    }
    // Newest first; the first link's secret is the one gone.
    expect(headers.cookie).toBe(`__Host-magic_link_tx=${pairs.slice(1).reverse().join('~')}`);
    const [oldest, kept] = mailer.sent.map(tokenOf);

    const refused = await inRequest(headers, () => service.consume(oldest));
    expect(refused.error).toBeInstanceOf(MagicLinkError);
    expect(refused.cookies).toEqual([]);
    expect(seen).toEqual([{ type: 'magic-link-refused', reason: 'not-this-browser' }]);

    await expect(inRequest(headers, () => service.consume(kept))).resolves.toMatchObject({ value: { session: { userId: 'u1' } } });
  });

  it('ignores whatever else the cookie holds', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader } = setup();
    const created = await inRequest({}, () => service.create('ada@example.com'));
    const pair = cookieHeader(created.cookies[0]).cookie.slice('__Host-magic_link_tx='.length);

    const opened = await inRequest({ cookie: `__Host-magic_link_tx=junk~a.b.c~${pair}` }, () => service.consume(tokenOf(mailer.sent[0])));
    expect(opened.value).toMatchObject({ session: { userId: 'u1' } });
    expect(opened.cookies[0]).toMatch(/^__Host-magic_link_tx=; Max-Age=0; /);
  });

  it('burns a link for an address nobody may sign in with, says so in the event, and clears the cookie', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, seen } = setup();
    const created = await inRequest({}, () => service.create('stranger@example.com'));
    const token = tokenOf(mailer.sent[0]);

    const refused = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(token));
    expect(refused).toEqual({ value: null, cookies: [expect.stringMatching(/^__Host-magic_link_tx=; Max-Age=0; /)] });
    expect(seen).toEqual([{ type: 'magic-link-refused', reason: 'refused', email: 'stranger@example.com' }]);

    mailer.known.set('stranger@example.com', { id: 'u9', email: 'stranger@example.com' }); // allowed now, but the link is spent
    const again = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(token));
    expect(again.value).toBeNull();
    expect(seen.at(-1)).toEqual({ type: 'magic-link-refused', reason: 'unknown' });
  });

  it('refuses to create a link from another site’s page, which would bind this browser to a link its author reads', async () => {
    const { service, inRequest, mailer, links } = setup();
    const save = vi.spyOn(links, 'saveMagicLink');

    // A form on the attacker's page, auto-submitted with their own address (login CSRF).
    const crossSite = await inRequest({ host: 'app.test', origin: 'https://evil.test', 'sec-fetch-site': 'cross-site' }, () =>
      service.create('attacker@example.com'),
    );
    expect(crossSite.error).toBeInstanceOf(ForbiddenException);
    expect(crossSite.cookies).toEqual([]);
    expect(save).not.toHaveBeenCalled();
    expect(mailer.sent).toEqual([]);

    const own = await inRequest({ host: 'app.test', origin: 'https://app.test', 'sec-fetch-site': 'same-origin' }, () =>
      service.create('ada@example.com'),
    );
    expect(own.cookies).toHaveLength(1);
  });

  describe('consume from a request of another origin', () => {
    const crossSite = { host: 'app.test', origin: 'https://evil.test', 'sec-fetch-site': 'cross-site' };
    const sameOrigin = { host: 'app.test', origin: 'https://app.test', 'sec-fetch-site': 'same-origin' };

    it('refuses before it spends the link or changes the transaction cookie, so the same link signs in afterwards', async () => {
      const { service, inRequest, mailer, tokenOf, cookieHeader, links, seen } = setup();
      const created = await inRequest({}, () => service.create('ada@example.com'));
      const token = tokenOf(mailer.sent[0]);
      const consume = vi.spyOn(links, 'consumeMagicLink');
      const cookie = cookieHeader(created.cookies[0]);

      const refused = await inRequest({ ...cookie, ...crossSite }, () => service.consume(token));

      expect(refused.error).toEqual(new ForbiddenException('Cross-origin sign-in refused'));
      expect(refused.cookies).toEqual([]);
      expect(consume).not.toHaveBeenCalled();
      expect(seen.filter((event) => event.type === 'magic-link-refused')).toEqual([]);

      const opened = await inRequest({ ...cookie, ...sameOrigin }, () => service.consume(token));
      expect(opened.value).toMatchObject({ session: { userId: 'u1' } });
    });

    it('answers the same refusal for a token that is not valid, or from a browser that did not ask, so it tells nothing', async () => {
      const { service, inRequest, mailer, tokenOf } = setup();
      await inRequest({}, () => service.create('ada@example.com'));

      const unknown = await inRequest(crossSite, () => service.consume('X'.repeat(43)));
      const malformed = await inRequest(crossSite, () => service.consume('not a token'));

      expect(unknown.error).toBeInstanceOf(ForbiddenException);
      expect(malformed.error).toBeInstanceOf(ForbiddenException);
      // A real link, opened without the cookie of the browser that asked: the origin answers first.
      const foreign = await inRequest(crossSite, () => service.consume(tokenOf(mailer.sent[0])));
      expect(foreign.error).toBeInstanceOf(ForbiddenException);
    });

    it('signs in a request of the app’s own origin', async () => {
      const { service, inRequest, mailer, tokenOf, cookieHeader } = setup();
      const created = await inRequest({}, () => service.create('ada@example.com'));

      const opened = await inRequest({ ...cookieHeader(created.cookies[0]), ...sameOrigin }, () => service.consume(tokenOf(mailer.sent[0])));

      expect(opened.value).toMatchObject({ session: { userId: 'u1' } });
    });
  });

  it('finds nothing for a link read from a log or forwarded, whatever cookie is forged for it', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, seen } = setup();
    const created = await inRequest({}, () => service.create('ada@example.com'));
    const token = tokenOf(mailer.sent[0]);
    const [hint] = cookieHeader(created.cookies[0]).cookie.split('=')[1].split('.'); // computable from the link

    // The SHA-256 of the token, which the cookie used to hold: not this browser's link.
    const byHash = await inRequest({ cookie: `__Host-magic_link_tx=${sha256(token)}` }, () => service.consume(token));
    expect(byHash.error).toBeInstanceOf(MagicLinkError);

    // The right hint and a guessed secret: nothing is stored under that.
    const guessed = await inRequest({ cookie: `__Host-magic_link_tx=${hint}.${'A'.repeat(43)}` }, () => service.consume(token));
    expect(guessed.value).toBeNull();
    expect(seen.at(-1)).toEqual({ type: 'magic-link-refused', reason: 'unknown' });

    // Neither burned it: it still signs in the browser that requested it.
    const opened = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(token));
    expect(opened.value).toMatchObject({ session: { userId: 'u1' } });
  });

  it('signs in only an account whose stored address is the one the link was sent to', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, seen } = setup();
    // A lookup that ignores accents, as MySQL's default collation does: `exämple.com` finds `example.com`.
    const folded = (email: string) => email.normalize('NFD').replace(/\p{M}/gu, '');
    mailer.resolveUser = (email: string) => (folded(email) === 'victim@example.com' ? { id: 'victim', email: 'victim@example.com' } : null);

    const created = await inRequest({}, () => service.create('victim@exämple.com'));
    expect(mailer.sent[0].email).toBe('victim@exämple.com'); // the attacker's mailbox, on their look-alike domain
    const consumed = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(consumed.value).toBeNull();
    expect(seen.at(-1)).toEqual({ type: 'magic-link-refused', reason: 'refused', email: 'victim@exämple.com' });

    // The case and the spaces of the stored address do not matter.
    mailer.resolveUser = () => ({ id: 'victim', email: ' Victim@Example.COM ' });
    const again = await inRequest({}, () => service.create('victim@example.com'));
    const signedIn = await inRequest(cookieHeader(again.cookies[0]), () => service.consume(tokenOf(mailer.sent[1])));
    expect(signedIn.value).toMatchObject({ session: { userId: 'victim' } });
  });

  it('needs the stored address from resolveUser(), and says so', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader } = setup();
    mailer.known.set('ada@example.com', { id: 'u1' } as never);
    const created = await inRequest({}, () => service.create('ada@example.com'));

    const consumed = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(consumed.error).toBeInstanceOf(TypeError);
    expect((consumed.error as Error).message).toMatch(/^MagicLinkHandler\.resolveUser\(\) must return the account’s stored `email`/);
  });

  it('creates and sends nothing for an address no mail should go to, with the same answer', async () => {
    const { service, inRequest, mailer } = setup();
    const unmailable = [
      'ada@example.com\r\nBcc: everyone@example.com',
      'a da@example.com',
      'no-at-sign',
      '@example.com',
      'ada@',
      `${'a'.repeat(243)}@example.com`, // 255 characters
    ];
    for (const email of unmailable) {
      expect(await inRequest({}, () => service.create(email))).toEqual({ value: { expiresAt: expect.any(Date) }, cookies: [] });
    }
    expect(mailer.sent).toEqual([]);

    await inRequest({}, () => service.create(`${'a'.repeat(242)}@example.com`)); // 254: the most RFC 5321 allows
    expect(mailer.sent).toHaveLength(1);
  });

  it('refuses a malformed token as unknown, before checking the browser', async () => {
    const { service, inRequest, seen } = setup();
    const refused = await inRequest({}, () => service.consume('not a token'));
    expect(refused).toEqual({ value: null, cookies: [] });
    expect(seen).toEqual([{ type: 'magic-link-refused', reason: 'unknown' }]);
  });

  it('with bindToBrowser: false, sets and clears no cookie, and signs in any browser', async () => {
    const { service, inRequest, mailer, tokenOf } = setup({ bindToBrowser: false });
    const created = await inRequest({}, () => service.create('ada@example.com'));
    expect(created).toEqual({ value: { expiresAt: expect.any(Date) }, cookies: [] });

    const consumed = await inRequest({}, () => service.consume(tokenOf(mailer.sent[0])));
    expect(consumed.cookies).toEqual([expect.stringMatching(/^sid=/)]);
  });

  it('prefers the request passed to consume() over the exchange’s', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader } = setup();
    const created = await inRequest({}, () => service.create('ada@example.com'));

    const consumed = await inRequest({}, () => service.consume(tokenOf(mailer.sent[0]), { request: { headers: cookieHeader(created.cookies[0]) } }));
    expect(consumed.value).toMatchObject({ session: { userId: 'u1' } });
  });

  it('accepts a link until the millisecond before `ttl` runs out', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, tick, seen } = setup();
    const first = await inRequest({}, () => service.create('ada@example.com'));
    tick(599_999);
    expect((await inRequest(cookieHeader(first.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])))).value).not.toBeNull();

    const second = await inRequest({}, () => service.create('ada@example.com'));
    tick(600_000);
    expect((await inRequest(cookieHeader(second.cookies[0]), () => service.consume(tokenOf(mailer.sent[1])))).value).toBeNull();
    expect(seen.at(-1)).toEqual({ type: 'magic-link-refused', reason: 'expired', email: 'ada@example.com' });
  });
});
