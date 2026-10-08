/**
 * Magic links over HTTP with the options the e2e suite leaves at their defaults, on Express
 * and Fastify: the transaction cookie a browser receives (`__Host-magic_link_tx` for
 * `magicLink.ttl`, cleared once the link is settled), expiry on the configured clock, which
 * `redirectTo` values survive, `bindToBrowser: false`, and the refusals operators see as events.
 */
import { Body, Controller, Get, HttpCode, Injectable, Module, Post, UnauthorizedException, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationEvents,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  MagicLinkHandler,
  MagicLinkService,
  Public,
  SessionCookieProvider,
  type AuthenticationEvent,
  type MagicLink,
  type MagicLinkOptions,
  type SessionRecord,
} from '../lib/index.js';

const MINUTE = 60_000;
let clock = Date.UTC(2026, 0, 1);
const outbox: MagicLink[] = [];

@Injectable()
class LinkMailer extends MagicLinkHandler {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerHandler('magicLink', this);
  }
  send(link: MagicLink) {
    outbox.push(link);
  }
  resolveUser(email: string) {
    return email.startsWith('blocked') ? null : { id: email.split('@')[0], email };
  }
}

@Injectable()
class SessionAuth extends SessionCookieProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return { id: session.userId };
  }
}

@Public()
@Controller('auth/magic')
class MagicLinkController {
  constructor(private readonly magicLinkService: MagicLinkService) {}

  @Post()
  @HttpCode(202)
  async request(@Body() body: { email: string; redirectTo?: string }) {
    await this.magicLinkService.create(body.email, { redirectTo: body.redirectTo });
  }

  @Post('consume')
  @HttpCode(200)
  async consume(@Body('token') token: string) {
    const result = await this.magicLinkService.consume(token);
    if (!result) {
      throw new UnauthorizedException('Invalid or expired link');
    }
    return { redirectTo: result.redirectTo ?? '/' };
  }
}

@Controller('me')
class MeController {
  @Get()
  me(@CurrentUser('id') id: string) {
    return { id };
  }
}

function appModule(magicLink: Partial<MagicLinkOptions> = {}) {
  @Module({
    imports: [AuthenticationModule.forRoot({ magicLink: { url: 'https://example.com/magic', ttl: '15m', now: () => clock, ...magicLink } })],
    controllers: [MagicLinkController, MeController],
    providers: [LinkMailer, SessionAuth],
  })
  class MagicLinkAppModule {}
  return MagicLinkAppModule;
}

const setCookies = (res: request.Response) => ([] as string[]).concat(res.headers['set-cookie'] ?? []);
const cookieNamed = (res: request.Response, name: string) => setCookies(res).find((c) => c.startsWith(`${name}=`));
const tokenOf = (link: MagicLink) => new URL(link.url).searchParams.get('token')!;

describe.each(adapters.map((a) => a.name))('magic links (%s)', (adapter) => {
  describe('bound to the browser (the default)', () => {
    let app: INestApplication;
    const events: AuthenticationEvent[] = [];
    const http = () => request(app.getHttpServer());

    beforeAll(async () => {
      app = await createApp(adapter, appModule());
      app.get(AuthenticationEvents).events$.subscribe((event) => events.push(event));
    });
    afterAll(() => app.close());
    beforeEach(() => {
      events.length = 0;
    });

    async function requestLink(email: string, redirectTo?: string) {
      const res = await http().post('/auth/magic').send({ email, redirectTo }).expect(202);
      const setCookie = cookieNamed(res, '__Host-magic_link_tx')!;
      return { setCookie, tx: setCookie.split(';')[0], token: tokenOf(outbox.at(-1)!), link: outbox.at(-1)! };
    }

    it('sets a __Host- transaction cookie for the link’s lifetime, and clears it once the link signed the browser in', async () => {
      const { setCookie, tx, token, link } = await requestLink(' Ada@Example.com ');

      expect(link).toEqual({ email: 'ada@example.com', url: `https://example.com/magic?token=${token}`, expiresAt: new Date(clock + 15 * MINUTE) });
      expect(setCookie).toMatch(/HttpOnly/i);
      expect(setCookie).toMatch(/SameSite=Lax/i);
      expect(setCookie).toMatch(/Max-Age=900/i);

      const consumed = await http().post('/auth/magic/consume').set('Cookie', tx).send({ token }).expect(200, { redirectTo: '/' });
      expect(cookieNamed(consumed, '__Host-magic_link_tx')).toMatch(/^__Host-magic_link_tx=;.*Max-Age=0/i);
      await http().get('/me').set('Cookie', cookieNamed(consumed, '__Host-sid')!.split(';')[0]).expect(200, { id: 'ada' });
    });

    it('keeps a same-origin path to return to, and drops anything that leaves the site', async () => {
      for (const [redirectTo, kept] of [
        ['/orders?page=2', '/orders?page=2'],
        ['https://evil.test/phish', '/'],
        ['//evil.test', '/'],
        ['/\\evil.test', '/'],
      ]) {
        const { tx, token } = await requestLink('grace@example.com', redirectTo);
        await http().post('/auth/magic/consume').set('Cookie', tx).send({ token }).expect(200, { redirectTo: kept });
      }
    });

    it('refuses an expired link, a used one and one for an address the app refuses, with one answer and an event each', async () => {
      const expired = await requestLink('linus@example.com');
      clock += 15 * MINUTE;
      await http().post('/auth/magic/consume').set('Cookie', expired.tx).send({ token: expired.token }).expect(401);

      const used = await requestLink('linus@example.com');
      await http().post('/auth/magic/consume').set('Cookie', used.tx).send({ token: used.token }).expect(200);
      const again = await http().post('/auth/magic/consume').set('Cookie', used.tx).send({ token: used.token }).expect(401);

      const blocked = await requestLink('blocked@example.com');
      const refused = await http().post('/auth/magic/consume').set('Cookie', blocked.tx).send({ token: blocked.token }).expect(401);

      expect(again.body).toEqual(refused.body);
      expect(events.filter((event) => event.type === 'magic-link-refused')).toEqual([
        { type: 'magic-link-refused', reason: 'expired', email: 'linus@example.com' },
        // A used link's cookie was cleared: the browser still sends it, but the id is gone.
        { type: 'magic-link-refused', reason: 'unknown' },
        { type: 'magic-link-refused', reason: 'refused', email: 'blocked@example.com' },
      ]);
    });

    it('answers a link opened in another browser with not_this_browser, and keeps it for the browser that asked', async () => {
      const { tx, token } = await requestLink('ada@example.com');

      const elsewhere = await http().post('/auth/magic/consume').send({ token }).expect(401);
      expect(elsewhere.body).toEqual({
        message: 'Open the link in the browser you requested it from, or request a new one here',
        error: 'not_this_browser',
        code: 'not_this_browser',
        statusCode: 401,
      });
      await http().post('/auth/magic/consume').set('Cookie', tx).send({ token }).expect(200);
    });
  });

  describe('bindToBrowser: false', () => {
    let app: INestApplication;

    beforeAll(async () => {
      app = await createApp(adapter, appModule({ bindToBrowser: false }));
    });
    afterAll(() => app.close());

    it('sets no transaction cookie, and signs in whichever browser opens the link, once', async () => {
      const requested = await request(app.getHttpServer()).post('/auth/magic').send({ email: 'ada@example.com' }).expect(202);
      expect(setCookies(requested)).toEqual([]);

      const token = tokenOf(outbox.at(-1)!);
      const phone = await request(app.getHttpServer()).post('/auth/magic/consume').send({ token }).expect(200);
      expect(cookieNamed(phone, '__Host-magic_link_tx')).toBeUndefined();
      await request(app.getHttpServer()).get('/me').set('Cookie', cookieNamed(phone, '__Host-sid')!.split(';')[0]).expect(200, { id: 'ada' });

      await request(app.getHttpServer()).post('/auth/magic/consume').send({ token }).expect(401);
    });
  });

  describe('a transaction cookie with a Domain', () => {
    it('is named magic_link_tx, without the __Host- prefix its attributes rule out', async () => {
      const app = await createApp(adapter, appModule({ cookie: { domain: 'example.com' } }));
      const requested = await request(app.getHttpServer()).post('/auth/magic').send({ email: 'ada@example.com' }).expect(202);

      expect(cookieNamed(requested, 'magic_link_tx')).toMatch(/Domain=example\.com/i);
      const token = tokenOf(outbox.at(-1)!);
      await request(app.getHttpServer())
        .post('/auth/magic/consume')
        .set('Cookie', cookieNamed(requested, 'magic_link_tx')!.split(';')[0])
        .send({ token })
        .expect(200);
      await app.close();
    });
  });
});
