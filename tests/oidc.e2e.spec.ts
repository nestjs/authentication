import { generateKeyPairSync } from 'node:crypto';
import { Controller, Get, Injectable, Module, NotFoundException, Param, Query, Redirect, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationEvents,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  InMemoryOidcStateStore,
  JwtSigner,
  MfaService,
  OidcAccountResolver,
  OidcService,
  Public,
  SessionService,
  SignInService,
  TokenService,
  github,
  microsoft,
  type AuthenticationEvent,
  type OidcOptions,
  type OidcProfile,
  type OidcRequest,
  type OidcResolveContext,
} from '../lib/index.js';
import { OidcError } from '../lib/errors/oidc.error.js';
import { sha256 } from '../lib/utils/crypto.util.js';
import { OidcClient } from '../lib/oidc/oidc.client.js';
import { SessionAuthModule, UsersModule, UsersRepository, registryWith, storageWith, type User } from './fixtures.js';
import { MockOidcProvider } from './mock-oidc.js';

const idp = new MockOidcProvider();
const linked: OidcProfile[] = [];
const contexts: OidcResolveContext[] = [];

@Injectable()
class AccountResolver extends OidcAccountResolver {
  // (provider, subject) → user id, as a real app would keep in an accounts table.
  private readonly identities = new Map([
    ['mock:alice-sub', 'u1'],
    ['github:4242', 'u2'],
  ]);

  constructor(
    private readonly users: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('oidc', this);
  }
  resolveUser(profile: OidcProfile, _tokens: unknown, context: OidcResolveContext) {
    linked.push(profile);
    contexts.push(context);

    const key = `${profile.provider}:${profile.subject}`;
    const owner = this.identities.get(key);
    if (context.linkTo) {
      if (owner && owner !== context.linkTo.id) {
        return null; // someone else's identity
      }
      this.identities.set(key, context.linkTo.id);
      return this.users.findById(context.linkTo.id) ?? null;
    }

    return owner ? (this.users.findById(owner) ?? null) : null;
  }
}

/** The app's routes: login and callback, calling OidcService (the README's controller, at any path). */
function oidcController(path: string) {
  @Public()
  @Controller(path)
  class OidcController {
    constructor(private readonly oidc: OidcService) {}

    @Get(':provider/login')
    @Redirect()
    login(@Param('provider') provider: string, @Query('redirectTo') redirectTo?: string, @Query('link') link?: string) {
      return this.oidc.start(provider, { redirectTo, link: link === 'true' });
    }

    @Get(':provider/callback')
    @Redirect()
    callback(@Param('provider') provider: string, @Query() query: Record<string, string>) {
      return this.oidc.finish(provider, query);
    }
  }

  return OidcController;
}

@Controller('me')
class MeController {
  @Get()
  me(@CurrentUser('id') id: string) {
    return { id };
  }
}

function appModule() {
  @Module({
    imports: [
      AuthenticationModule.forRootAsync({
        useFactory: () => ({
          session: {
            cookie: { secure: false },
            // The same hook as every other sign-in: nothing OIDC-specific to configure.
            metadata: ({ headers }) => ({ userAgent: headers['user-agent'] ?? null }),
          },
          password: { logN: 10 },
          oidc: {
            callbackUrl: 'http://app.test/auth/oidc/:provider/callback',
            cookie: { secure: false },
            jwks: { cooldown: 0 },
            providers: {
              mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret },
              github: {
                ...github({ clientId: idp.clientId, clientSecret: idp.clientSecret }),
                authorizationEndpoint: `${idp.issuer}/gh/authorize`,
                tokenEndpoint: `${idp.issuer}/gh/token`,
                userinfoEndpoint: `${idp.issuer}/gh/user`,
              },
            },
          },
        }),
      }),
      UsersModule,
      SessionAuthModule,
    ],
    controllers: [MeController, oidcController('auth/oidc')],
    providers: [AccountResolver],
  })
  class OidcAppModule {}
  return OidcAppModule;
}

const cookies = (res: request.Response) => ([] as string[]).concat(res.headers['set-cookie'] ?? []);
const cookie = (res: request.Response, name: string) => cookies(res).find((c) => c.startsWith(`${name}=`))?.split(';')[0];

beforeAll(() => idp.start());
afterAll(() => idp.stop());

describe.each(adapters.map((a) => a.name))('OIDC sign-in (%s)', (adapter) => {
  let app: INestApplication;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    app = await createApp(adapter, appModule());
  });
  afterAll(() => app.close());

  async function begin(provider = 'mock', redirectTo?: string, { link, sid }: { link?: boolean; sid?: string } = {}) {
    let req = http()
      .get(`/auth/oidc/${provider}/login`)
      .query({ ...(redirectTo && { redirectTo }), ...(link && { link: 'true' }) });
    if (sid) {
      req = req.set('Cookie', sid);
    }

    const res = await req.expect(302);
    const location = res.headers.location as string;
    return { location, params: new URL(location).searchParams, tx: cookie(res, 'oidc_tx')! };
  }

  const callback = (provider: string, query: Record<string, string>, ...cookies: (string | undefined)[]) => {
    const req = http().get(`/auth/oidc/${provider}/callback`).query(query);
    const header = cookies.filter(Boolean).join('; ');
    return header ? req.set('Cookie', header) : req;
  };

  async function signInAs(sub: string) {
    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub });
    return cookie(await callback('mock', { code, state: params.get('state')! }, tx).expect(302), 'sid')!;
  }

  it('redirects to the IdP with PKCE (S256), state and nonce', async () => {
    const { location, params, tx } = await begin();

    expect(location.startsWith(`${idp.issuer}/authorize?`)).toBe(true);
    expect(Object.fromEntries(params)).toMatchObject({
      response_type: 'code',
      client_id: idp.clientId,
      redirect_uri: 'http://app.test/auth/oidc/mock/callback',
      scope: 'openid email profile',
      code_challenge_method: 'S256',
    });
    expect(params.get('code_challenge')).toMatch(/^[\w-]{43}$/);
    expect(params.get('nonce')).toMatch(/^[\w-]{43}$/);
    // The cookie holds the secret whose SHA-256 is the state: never the state, which URLs carry.
    const binding = tx.slice('oidc_tx='.length);
    expect(binding).toMatch(/^[\w-]{43}$/);
    expect(binding).not.toBe(params.get('state'));
    expect(sha256(binding)).toBe(params.get('state'));
  });

  it('completes the flow: session cookie, tx cookie cleared, safe redirect', async () => {
    const { location, params, tx } = await begin('mock', '/dashboard');
    const code = idp.approve(location, { sub: 'alice-sub' });
    const res = await callback('mock', { code, state: params.get('state')! }, tx).expect(302);

    expect(res.headers.location).toBe('/dashboard');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(cookies(res)).toContainEqual(expect.stringMatching(/^oidc_tx=; Max-Age=0;/));

    const sid = cookie(res, 'sid')!;
    await http().get('/me').set('Cookie', sid).expect(200, { id: 'u1' });

    expect(linked.at(-1)).toMatchObject({
      provider: 'mock',
      subject: 'alice-sub',
      email: 'alice-sub@idp.test',
      emailVerified: true,
      name: 'From Userinfo',
    });
  });

  it('verifies ES256 ID tokens too', async () => {
    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub', alg: 'ES256' });
    await callback('mock', { code, state: params.get('state')! }, tx).expect(302);
  });

  it('ignores open redirects', async () => {
    const { location, params, tx } = await begin('mock', '//evil.test/x');
    const code = idp.approve(location, { sub: 'alice-sub' });
    const res = await callback('mock', { code, state: params.get('state')! }, tx).expect(302);
    expect(res.headers.location).toBe('/');
  });

  describe('binding and replay', () => {
    it('rejects a callback without the browser’s transaction cookie (login CSRF)', async () => {
      const { location, params } = await begin();
      const code = idp.approve(location, { sub: 'alice-sub' });
      await callback('mock', { code, state: params.get('state')! }).expect(400);
    });

    it('rejects a state that belongs to another login', async () => {
      const first = await begin();
      const second = await begin();
      const code = idp.approve(first.location, { sub: 'alice-sub' });
      await callback('mock', { code, state: first.params.get('state')! }, second.tx).expect(400);
    });

    it('rejects a replayed callback', async () => {
      const { location, params, tx } = await begin();
      const code = idp.approve(location, { sub: 'alice-sub' });
      await callback('mock', { code, state: params.get('state')! }, tx).expect(302);
      await callback('mock', { code, state: params.get('state')! }, tx).expect(400);
    });

    it('refuses a callback URL replayed from another client with the state as its cookie (a leaked URL)', async () => {
      // The victim's callback failed (a second tab replaced the cookie), and its URL sits in a log.
      const victim = await begin();
      await begin(); // the second tab
      const code = idp.approve(victim.location, { sub: 'alice-sub' });
      const state = victim.params.get('state')!;

      // Whoever reads the URL knows the state, never the secret the cookie holds.
      const forged = await callback('mock', { code, state }, `oidc_tx=${state}`).expect(400);
      expect(forged.body.message).toBe('state mismatch');
      expect(cookie(forged, 'sid')).toBeUndefined();

      // The login is still the victim's to finish.
      await callback('mock', { code, state }, victim.tx).expect(302);
    });

    it('rejects a transaction started for another provider', async () => {
      const { location, params, tx } = await begin('mock');
      const code = idp.approve(location, { sub: 'alice-sub' });
      await callback('github', { code, state: params.get('state')! }, tx).expect(400);
    });
  });

  describe('IdP responses that fail verification', () => {
    const attempt = async (
      status: number,
      options: Parameters<MockOidcProvider['approve']>[1],
      extra: Record<string, string> = {},
    ) => {
      const { location, params, tx } = await begin();
      const code = idp.approve(location, options);
      return callback('mock', { code, state: params.get('state')!, ...extra }, tx).expect(status);
    };

    it.each([
      ['nonce mismatch', { idToken: { nonce: 'other' } }, /nonce/],
      ['wrong audience', { idToken: { aud: 'someone-else' } }, /audience/],
      ['multiple audiences without azp', { idToken: { aud: ['nest-client', 'other'] } }, /azp/],
      ['expired', { idToken: { exp: Math.floor(Date.now() / 1000) - 120 } }, /expired/],
      ['wrong issuer', { idToken: { iss: 'https://evil.test' } }, /issuer/],
      ['foreign signing key', { signWith: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey }, /signature/],
      ['userinfo for another subject', { userinfoSub: 'mallory' }, /subject mismatch/],
      ['PKCE verifier mismatch', { codeChallenge: 'A'.repeat(43) }, /rejected the code/],
    ] as const)('%s → 401', async (_, options, message) => {
      const res = await attempt(401, { sub: 'alice-sub', ...options });
      expect(res.body.message).toMatch(message);
      expect(cookie(res, 'sid')).toBeUndefined();
    });

    it('rejects an `iss` response parameter from another issuer (RFC 9207) → 400', async () => {
      await attempt(400, { sub: 'alice-sub' }, { iss: 'https://evil.test' });
    });

    it('passes IdP errors through as 400', async () => {
      const { params, tx } = await begin();
      await callback('mock', { error: 'access_denied', state: params.get('state')! }, tx).expect(400);
    });

    it.each([
      ['token', 'token endpoint unavailable (503)'],
      ['userinfo', `userinfo endpoint unavailable (503)`],
    ] as const)('answers 502, not 401, when the %s endpoint is down', async (endpoint, message) => {
      const { location, params, tx } = await begin();
      const code = idp.approve(location, { sub: 'alice-sub' });

      idp.down = endpoint;
      try {
        const res = await callback('mock', { code, state: params.get('state')! }, tx).expect(502);
        expect(res.body).toEqual({ message, error: 'Bad Gateway', statusCode: 502 });
      } finally {
        idp.down = undefined;
      }
    });

    it('lets the resolver refuse an account → 403', async () => {
      await attempt(403, { sub: 'unknown-sub' });
    });
  });

  it('follows JWKS key rotation', async () => {
    idp.rotateRsaKey();
    const before = idp.jwksRequests;

    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub' });
    await callback('mock', { code, state: params.get('state')! }, tx).expect(302);

    expect(idp.jwksRequests).toBe(before + 1);
  });

  it('signs in with GitHub (OAuth 2.0), taking the primary verified email', async () => {
    const { location, params, tx } = await begin('github');

    expect(location.startsWith(`${idp.issuer}/gh/authorize?`)).toBe(true);
    expect(params.get('nonce')).toBeNull();
    expect(params.get('scope')).toBe('read:user user:email');

    const code = idp.approve(location, { sub: 'ignored' });
    const res = await callback('github', { code, state: params.get('state')! }, tx).expect(302);

    await http().get('/me').set('Cookie', cookie(res, 'sid')!).expect(200, { id: 'u2' });
    expect(linked.at(-1)).toMatchObject({ provider: 'github', subject: '4242', email: 'octo@example.com', emailVerified: true, name: 'octocat' });
  });

  it('signs in through SignInService: `session.metadata`, the sign-in event, an empty resolver context', async () => {
    const events: AuthenticationEvent[] = [];
    const subscription = app.get(AuthenticationEvents).events$.subscribe((event) => events.push(event));

    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub' });
    await callback('mock', { code, state: params.get('state')! }, tx).set('User-Agent', 'Browser/1.0').expect(302);
    subscription.unsubscribe();

    expect(contexts.at(-1)).toEqual({});

    const sessions = await app.get(SessionService).list('u1');
    expect(sessions.at(-1)!.metadata).toEqual({ userAgent: 'Browser/1.0' });
    expect(events).toEqual([
      {
        type: 'sign-in',
        userId: 'u1',
        sessionId: sessions.at(-1)!.id,
        method: 'oidc:mock',
        metadata: { userAgent: 'Browser/1.0' },
      },
    ]);
  });

  it('replaces the browser’s previous session (fixation defence)', async () => {
    const before = await signInAs('alice-sub');

    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub' });
    const res = await callback('mock', { code, state: params.get('state')! }, tx, before).expect(302);

    await http().get('/me').set('Cookie', before).expect(401);
    await http().get('/me').set('Cookie', cookie(res, 'sid')!).expect(200, { id: 'u1' });
  });

  describe('linking to the signed-in user (?link=true)', () => {
    it('links a new identity to the session’s user and keeps the session', async () => {
      const sid = await signInAs('alice-sub');

      const { location, params, tx } = await begin('mock', '/settings', { link: true, sid });
      const code = idp.approve(location, { sub: 'alice-second-account' });
      const res = await callback('mock', { code, state: params.get('state')! }, tx, sid).expect(302);

      expect(res.headers.location).toBe('/settings');
      expect(cookie(res, 'sid')).toBeUndefined(); // not a new sign-in
      expect(contexts.at(-1)).toEqual({ linkTo: { id: 'u1' } });
      await http().get('/me').set('Cookie', sid).expect(200, { id: 'u1' });

      // The linked identity now signs in to the same account.
      await http().get('/me').set('Cookie', await signInAs('alice-second-account')).expect(200, { id: 'u1' });
    });

    it('refuses to start from another site’s page, which would link whatever account the IdP has signed in', async () => {
      const sid = await signInAs('alice-sub');
      const crossSite = await http()
        .get('/auth/oidc/mock/login')
        .query({ link: 'true' })
        .set('Cookie', sid)
        .set('Sec-Fetch-Site', 'cross-site')
        .expect(403);
      expect(crossSite.body.message).toBe('Cross-site link refused');
      expect(cookie(crossSite, 'oidc_tx')).toBeUndefined();

      // From the app's own pages, or typed in: allowed.
      for (const site of ['same-origin', 'same-site', 'none']) {
        await http().get('/auth/oidc/mock/login').query({ link: 'true' }).set('Cookie', sid).set('Sec-Fetch-Site', site).expect(302);
      }
    });

    it('needs a signed-in session to start', async () => {
      await http().get('/auth/oidc/mock/login').query({ link: 'true' }).expect(401);
      await http().get('/auth/oidc/mock/login').query({ link: 'true' }).set('Cookie', `sid=${'x'.repeat(43)}`).expect(401);
    });

    it('refuses the callback when the session that started it is gone', async () => {
      const sid = await signInAs('alice-sub');
      const { location, params, tx } = await begin('mock', undefined, { link: true, sid });

      await app.get(SessionService).revokeAll('u1');

      const code = idp.approve(location, { sub: 'late-link-sub' });
      await callback('mock', { code, state: params.get('state')! }, tx, sid).expect(401);
      await callback('mock', { code, state: params.get('state')! }, tx).expect(400); // spent
    });

    it('refuses an identity that belongs to another user → 403', async () => {
      const sid = await signInAs('alice-sub');
      const { location, params, tx } = await begin('mock', undefined, { link: true, sid });
      const code = idp.approve(location, { sub: 'bob-sub-taken' });
      (app.get(AccountResolver) as any).identities.set('mock:bob-sub-taken', 'u2');

      await callback('mock', { code, state: params.get('state')! }, tx, sid).expect(403);
    });
  });

  it('answers 404 for unknown providers', async () => {
    await http().get('/auth/oidc/nope/login').expect(404);
    await http().get('/auth/oidc/__proto__/login').expect(404);
  });
});

describe.each(adapters.map((a) => a.name))('OIDC routes at another path, forRoot (%s)', (adapter) => {
  let app: INestApplication;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    @Injectable()
    class AnyoneIsAlice extends OidcAccountResolver {
      constructor(registry: AuthenticationRegistry) {
        super();
        registry.registerHandler('oidc', this);
      }
      resolveUser() {
        return { id: 'u1' };
      }
    }

    @Module({
      imports: [
        AuthenticationModule.forRoot({
          session: { cookie: { secure: false } },
          password: { logN: 10 },
          oidc: {
            callbackUrl: 'http://app.test/sso/:provider/callback',
            cookie: { secure: false },
            providers: { mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret } },
          },
        }),
        UsersModule,
        SessionAuthModule,
      ],
      controllers: [MeController, oidcController('sso')],
      providers: [AnyoneIsAlice],
    })
    class SsoModule {}

    app = await createApp(adapter, SsoModule);
  });
  afterAll(() => app.close());

  it('signs in through the routes the app declares, with the callbackUrl it configures', async () => {
    const login = await http().get('/sso/mock/login').expect(302);
    expect(login.headers['cache-control']).toBe('no-store');

    const params = new URL(login.headers.location).searchParams;
    expect(params.get('redirect_uri')).toBe('http://app.test/sso/mock/callback');

    const code = idp.approve(login.headers.location, { sub: 'anyone' });
    const res = await http()
      .get('/sso/mock/callback')
      .query({ code, state: params.get('state')! })
      .set('Cookie', cookie(login, 'oidc_tx')!)
      .expect(302);
    await http().get('/me').set('Cookie', cookie(res, 'sid')!).expect(200, { id: 'u1' });

    // The package mounts no routes of its own.
    await http().get('/auth/oidc/mock/login').expect(404);
  });
});

describe.each(adapters.map((a) => a.name))('OIDC on several domains, callbackUrl from the request (%s)', (adapter) => {
  const domains = ['tenant-a.test', 'tenant-b.test'];
  let app: INestApplication;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    @Injectable()
    class AnyoneIsAlice extends OidcAccountResolver {
      constructor(registry: AuthenticationRegistry) {
        super();
        registry.registerHandler('oidc', this);
      }
      resolveUser() {
        return { id: 'u1' };
      }
    }

    @Module({
      imports: [
        AuthenticationModule.forRoot({
          session: { cookie: { secure: false } },
          password: { logN: 10 },
          oidc: {
            // The app's own list of domains, never the header as it came.
            callbackUrl: ({ headers }) => {
              const host = domains.find((domain) => domain === headers.host);
              if (!host) {
                throw new NotFoundException();
              }
              return `http://${host}/auth/oidc/:provider/callback`;
            },
            cookie: { secure: false },
            providers: { mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret } },
          },
        }),
        UsersModule,
        SessionAuthModule,
      ],
      controllers: [MeController, oidcController('auth/oidc')],
      providers: [AnyoneIsAlice],
    })
    class MultiDomainModule {}

    app = await createApp(adapter, MultiDomainModule);
  });
  afterAll(() => app.close());

  async function begin(host: string) {
    const login = await http().get('/auth/oidc/mock/login').set('Host', host).expect(302);
    const params = new URL(login.headers.location).searchParams;
    return { location: login.headers.location as string, params, tx: cookie(login, 'oidc_tx')! };
  }

  it.each(domains)('signs in on %s, with that domain’s callback URL', async (host) => {
    const { location, params, tx } = await begin(host);
    expect(params.get('redirect_uri')).toBe(`http://${host}/auth/oidc/mock/callback`);

    const code = idp.approve(location, { sub: 'anyone' });
    const res = await http()
      .get('/auth/oidc/mock/callback')
      .set('Host', host)
      .set('Cookie', tx)
      .query({ code, state: params.get('state')! })
      .expect(302);
    await http().get('/me').set('Cookie', cookie(res, 'sid')!).expect(200, { id: 'u1' });
  });

  it('fails a callback that reaches another domain than the login: the provider refuses the code', async () => {
    const { location, params, tx } = await begin('tenant-a.test');
    const code = idp.approve(location, { sub: 'anyone' });

    await http()
      .get('/auth/oidc/mock/callback')
      .set('Host', 'tenant-b.test')
      .set('Cookie', tx)
      .query({ code, state: params.get('state')! })
      .expect(401);
  });

  it('answers what the function throws for a domain it does not serve', async () => {
    await http().get('/auth/oidc/mock/login').set('Host', 'evil.test').expect(404);
  });
});

describe('OidcService', () => {
  const binding = 'S'.repeat(43);
  const state = sha256(binding);
  function setup(oidc: Partial<OidcOptions> = {}) {
    const store = new InMemoryOidcStateStore();
    const storage = storageWith({ oidcStates: store });
    const sessions = new SessionService(storage, {});
    const signIn = new SignInService(sessions, new MfaService(storage, {}), new TokenService(storage, {}));

    const resolver = new (class extends OidcAccountResolver {
      resolveUser() {
        return { id: 'u1' };
      }
    })();

    const providers = { mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret } };
    const options = { oidc: { callbackUrl: 'https://app.test/auth/oidc/:provider/callback', providers, ...oidc } };
    const service = new OidcService(storage, registryWith(options, { oidc: resolver }), signIn, sessions, options);

    return { store, service };
  }

  it('names the transaction cookie __Host-oidc_tx when it is Secure, so no subdomain can plant one', async () => {
    const { cookies } = await setup().service.start('mock', { request: { method: 'GET', headers: {} } });
    expect(cookies).toEqual([expect.stringMatching(/^__Host-oidc_tx=[\w-]{43}; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/)]);
  });

  it('returns the session cookie with the transaction cookie, for callers outside HTTP', async () => {
    const { service } = setup();
    const login = await service.start('mock', { request: { method: 'GET', headers: {} } });
    const code = idp.approve(login.url, { sub: 'alice-sub' });
    const request = { method: 'GET', headers: { cookie: login.cookies[0].split(';')[0] } };

    const finished = await service.finish('mock', { state: new URL(login.url).searchParams.get('state'), code }, { request });
    expect(finished.cookies).toEqual([
      expect.stringMatching(/^__Host-sid=[\w-]{43}; Max-Age=\d+; Path=\/; HttpOnly; Secure; SameSite=Lax$/),
      expect.stringMatching(/^__Host-oidc_tx=; Max-Age=0; /),
    ]);
  });

  it('expires logins by the configured clock', async () => {
    let clock = Date.now();
    const { store, service } = setup({ now: () => clock });
    await store.saveOidcState({ state, provider: 'mock', codeVerifier: 'v', nonce: 'n', createdAt: new Date(clock), expiresAt: new Date(clock + 1_000) });

    clock += 2_000;

    const request = { method: 'GET', headers: { cookie: `__Host-oidc_tx=${binding}` } };
    await expect(service.finish('mock', { state, code: 'c' }, { request })).rejects.toThrow('unknown or expired login');
  });

  it('checks oidc.callbackUrl at startup', () => {
    expect(() => setup({ callbackUrl: '/auth/oidc/:provider/callback' })).toThrow(
      "OidcService: `oidc.callbackUrl` must be the absolute URL of your callback route, with `:provider` where the provider's name goes",
    );
  });

  it('asks a callbackUrl function on each login, with the request, and checks what it returns', async () => {
    const callbackUrl = vi.fn(({ headers }: OidcRequest) => `https://${headers.host}/auth/oidc/:provider/callback`);
    const { service } = setup({ callbackUrl });

    const login = await service.start('mock', { request: { method: 'GET', headers: { host: 'tenant-a.test' } } });
    expect(new URL(login.url).searchParams.get('redirect_uri')).toBe('https://tenant-a.test/auth/oidc/mock/callback');
    expect(callbackUrl).toHaveBeenCalledWith({ method: 'GET', headers: { host: 'tenant-a.test' } });

    callbackUrl.mockResolvedValueOnce('/auth/oidc/:provider/callback');
    await expect(service.start('mock', { request: { method: 'GET', headers: {} } })).rejects.toThrow(
      "OidcService: the `oidc.callbackUrl` function must return the absolute URL of your callback route, with `:provider` where the provider's name goes",
    );
  });

  it('checks each provider’s credentials at startup; a public client says so', () => {
    const mock = { issuer: idp.issuer, clientId: idp.clientId };
    expect(() => setup({ providers: { mock } })).toThrow(
      "AuthenticationModule: `oidc.providers.mock.clientSecret` is required (the client secret the provider issued; a public " +
        "client sets `tokenEndpointAuthMethod: 'none'` instead), but it is undefined: is the environment variable it reads set?",
    );

    expect(() => setup({ providers: { mock: { ...mock, tokenEndpointAuthMethod: 'none' } } })).not.toThrow();

    expect(() => setup({ providers: { mock: { ...mock, clientId: '', clientSecret: 's' } } })).toThrow(
      '`oidc.providers.mock.clientId` is required (the client id the provider issued), but it is empty',
    );
  });

  it('throws when OpenID Connect is not enabled', async () => {
    const storage = storageWith();
    const sessions = new SessionService(storage, {});
    const signIn = new SignInService(sessions, new MfaService(storage, {}), new TokenService(storage, {}));
    const service = new OidcService(storage, registryWith(), signIn, sessions, {});

    await expect(service.start('mock')).rejects.toThrow(
      "OidcService: OpenID Connect is not enabled. Configure `oidc` in the AuthenticationModule options, and register an OidcAccountResolver: `registry.registerHandler('oidc', this)`.",
    );
  });
});

describe('OidcClient: what it refuses from a provider', () => {
  const ISSUER = 'https://idp.example.com';
  const REDIRECT = 'https://app.test/auth/oidc/idp/callback';
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });

  interface Behaviour {
    /** Merged into the discovery document. */
    document?: Record<string, unknown>;
    /** Merged into the token response (`undefined` drops a member). */
    token?: Record<string, unknown>;
    /** Merged into the ID token's claims. */
    claims?: Record<string, unknown>;
    /** Merged into the userinfo response. */
    userinfo?: Record<string, unknown>;
    /** Paths that answer with this status, or fail as a network error would. */
    fail?: Record<string, number | 'network'>;
  }

  /** A provider behind a stub `fetch`, and the client that talks to it. */
  function provider({ document = {}, token = {}, claims = {}, userinfo = {}, fail = {} }: Behaviour = {}) {
    let nonce = '';
    const fetch = (async (input: string | URL) => {
      const { pathname } = new URL(String(input));
      const failure = fail[pathname];
      if (failure === 'network') {
        throw new TypeError('fetch failed');
      }
      if (failure !== undefined) {
        return Response.json({}, { status: failure });
      }

      switch (pathname) {
        case '/.well-known/openid-configuration':
          return Response.json({
            issuer: ISSUER,
            authorization_endpoint: `${ISSUER}/authorize`,
            token_endpoint: `${ISSUER}/token`,
            jwks_uri: `${ISSUER}/jwks`,
            ...document,
          });
        case '/jwks':
          return Response.json({ keys: [{ ...rsa.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig' }] });
        case '/token': {
          const signer = new JwtSigner({ key: rsa.privateKey, kid: 'k1', issuer: ISSUER, audience: 'client', ttl: '5m' });
          const idToken = signer.sign({ sub: 'alice', nonce, email: 'alice@example.com', ...claims });
          return Response.json({ access_token: 'at', token_type: 'Bearer', id_token: idToken, ...token });
        }
        case '/userinfo':
          return Response.json({ sub: 'alice', ...userinfo });
        default:
          return Response.json({}, { status: 404 });
      }
    }) as typeof globalThis.fetch;

    const client = new OidcClient('idp', { issuer: ISSUER, clientId: 'client', clientSecret: 'secret' }, { fetch });
    return {
      client,
      async callback(params: Record<string, unknown> = {}) {
        const { transaction } = await client.authorizationRequest(REDIRECT);
        nonce = transaction.nonce!;
        return client.callback({ code: 'the-code', state: transaction.state, ...params }, transaction, REDIRECT);
      },
    };
  }

  async function refusal(promise: Promise<unknown>): Promise<Pick<OidcError, 'kind' | 'message'>> {
    const error = await promise.then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(OidcError);
    const { kind, message } = error as OidcError;
    return { kind, message };
  }

  it('signs in with a well-behaved provider (the baseline the cases below break)', async () => {
    const { profile } = await provider().callback();
    expect(profile).toMatchObject({ provider: 'idp', subject: 'alice', email: 'alice@example.com', emailVerified: false });
  });

  it('refuses a discovery document that names another issuer, or that it cannot load (OIDC Discovery §4.3)', async () => {
    const other = provider({ document: { issuer: 'https://evil.example.com' } });
    expect(await refusal(other.callback())).toEqual({ kind: 'unavailable', message: 'discovery issuer mismatch' });

    const down = provider({ fail: { '/.well-known/openid-configuration': 503 } });
    expect(await refusal(down.callback())).toEqual({ kind: 'unavailable', message: 'discovery failed (503)' });
  });

  it('refuses endpoints that are not https, except on loopback, as a misconfiguration (502), not a failed sign-in', async () => {
    const http = provider({ document: { token_endpoint: 'http://idp.example.com/token' } });
    expect(await refusal(http.callback())).toEqual({ kind: 'unavailable', message: 'token_endpoint must use https' });

    const garbage = provider({ document: { authorization_endpoint: 'not a url' } });
    expect(await refusal(garbage.callback())).toEqual({ kind: 'unavailable', message: 'authorization_endpoint is not a URL' });

    const keys = provider({ document: { jwks_uri: 'http://idp.example.com/jwks' } });
    expect(await refusal(keys.callback())).toEqual({ kind: 'unavailable', message: 'jwks_uri must use https' });
  });

  it('requires the `iss` response parameter from a provider that says it sends one (RFC 9207 mix-up defence)', async () => {
    const strict = provider({ document: { authorization_response_iss_parameter_supported: true } });
    expect(await refusal(strict.callback())).toEqual({ kind: 'request', message: 'missing iss' });
    await expect(strict.callback({ iss: ISSUER })).resolves.toMatchObject({ profile: { subject: 'alice' } });
  });

  it('refuses a callback without a code', async () => {
    expect(await refusal(provider().callback({ code: undefined }))).toEqual({ kind: 'request', message: 'missing code' });
    expect(await refusal(provider().callback({ code: '' }))).toEqual({ kind: 'request', message: 'missing code' });
  });

  it('refuses token responses without an ID token, an access token or the Bearer type', async () => {
    const cases: [Record<string, unknown>, string][] = [
      [{ id_token: undefined }, 'missing id_token'],
      [{ access_token: undefined }, 'malformed token response'],
      [{ token_type: 'mac' }, 'malformed token response'],
      [{ token_type: undefined }, 'malformed token response'],
    ];
    for (const [token, message] of cases) {
      expect(await refusal(provider({ token }).callback())).toEqual({ kind: 'verification', message });
    }
  });

  it('refuses an ID token with an empty subject, or issued to another party (`azp`)', async () => {
    expect(await refusal(provider({ claims: { sub: '' } }).callback())).toEqual({
      kind: 'verification',
      message: 'id_token without subject',
    });
    expect(await refusal(provider({ claims: { azp: 'another-client' } }).callback())).toEqual({
      kind: 'verification',
      message: 'id_token azp mismatch',
    });
  });

  it('takes an address as verified only on a boolean `true`, and the ID token’s claims over userinfo’s', async () => {
    const document = { userinfo_endpoint: `${ISSUER}/userinfo` };
    const quoted = provider({ document, userinfo: { email_verified: 'true' } });
    expect((await quoted.callback()).profile.emailVerified).toBe(false);

    const conflicting = provider({ document, claims: { email_verified: true }, userinfo: { email: 'mallory@example.com', email_verified: false } });
    expect((await conflicting.callback()).profile).toMatchObject({ email: 'alice@example.com', emailVerified: true });
  });

  it('takes the address and its `email_verified` from one source, never one from each', async () => {
    const document = { userinfo_endpoint: `${ISSUER}/userinfo` };
    // The ID token names an address it does not vouch for; userinfo vouches for another one.
    const split = provider({ document, claims: { email: 'ceo@victim.example' }, userinfo: { email: 'mallory@idp.example', email_verified: true } });
    expect((await split.callback()).profile).toMatchObject({ email: 'ceo@victim.example', emailVerified: false });

    // No address in the ID token: userinfo's, with its own flag.
    const fromUserinfo = provider({ document, claims: { email: undefined }, userinfo: { email: 'bob@example.com', email_verified: true } });
    expect((await fromUserinfo.callback()).profile).toMatchObject({ email: 'bob@example.com', emailVerified: true });

    // A flag with no address verifies nothing.
    const flagOnly = provider({ claims: { email: undefined, email_verified: true } });
    expect((await flagOnly.callback()).profile).toMatchObject({ email: undefined, emailVerified: false });
  });

  it('names only the host and path of an API call that failed, never its query', async () => {
    const fetch = (async (input: string | URL) =>
      new URL(String(input)).pathname === '/token'
        ? Response.json({ access_token: 'at', token_type: 'bearer' })
        : Response.json({}, { status: 403 })) as typeof globalThis.fetch;
    const client = new OidcClient(
      'api',
      {
        kind: 'oauth2',
        clientId: 'client',
        clientSecret: 'secret',
        authorizationEndpoint: `${ISSUER}/authorize`,
        tokenEndpoint: `${ISSUER}/token`,
        profile: (_, { fetchJson }) => fetchJson(`${ISSUER}/me?access_token=AT-123&appsecret_proof=deadbeef`),
      },
      { fetch },
    );
    const { transaction } = await client.authorizationRequest(REDIRECT);

    const error = await refusal(client.callback({ code: 'c' }, transaction, REDIRECT));
    expect(error).toEqual({ kind: 'verification', message: 'idp.example.com/me answered 403' });
  });

  it('answers an outage with `unavailable` (502), and a refusal with `verification` (401)', async () => {
    const unreachable = provider({ fail: { '/token': 'network' } });
    expect(await refusal(unreachable.callback())).toEqual({
      kind: 'unavailable',
      message: 'idp.example.com is unreachable (fetch failed)',
    });

    const refused = provider({ document: { userinfo_endpoint: `${ISSUER}/userinfo` }, fail: { '/userinfo': 401 } });
    expect(await refusal(refused.callback())).toEqual({ kind: 'verification', message: 'userinfo endpoint answered 401' });

    // Its key set down: an outage too, not a server error.
    const keysDown = provider({ fail: { '/jwks': 503 } });
    expect(await refusal(keysDown.callback())).toEqual({
      kind: 'unavailable',
      message: `JWKS ${ISSUER}/jwks is unavailable: it answered 503`,
    });
  });

  it('checks its configuration when it is created', () => {
    expect(() => new OidcClient('idp', { clientId: 'client' })).toThrow("OIDC provider 'idp' needs an issuer");
    expect(() => new OidcClient('gh', { kind: 'oauth2', clientId: 'client', tokenEndpoint: 'https://gh.test/token' })).toThrow(
      "OAuth 2.0 provider 'gh' needs authorizationEndpoint, tokenEndpoint and profile()",
    );
  });
});

describe('presets', () => {
  it('takes a Microsoft tenant by its id: a domain, or a multi-tenant endpoint, publishes another issuer', () => {
    // Discovery for `contoso.onmicrosoft.com` names `https://login.microsoftonline.com/<its GUID>/v2.0`.
    for (const tenant of ['common', 'organizations', 'consumers', 'contoso.onmicrosoft.com', 'Common', '']) {
      expect(() => microsoft({ tenant, clientId: 'a', clientSecret: 'b' })).toThrow(/^microsoft\(\): pass the tenant id, a GUID/);
    }
    expect(microsoft({ tenant: '72F988BF-86F1-41AF-91AB-2D7CD011DB47', clientId: 'a', clientSecret: 'b' }).issuer).toBe(
      'https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0',
    );
  });

  it('takes from GitHub only an address flagged primary and verified with booleans', async () => {
    const preset = github({ clientId: 'a', clientSecret: 'b' });
    const profileOf = (emails: unknown) =>
      preset.profile!({ id: 7, login: 'octo' }, { provider: 'github', tokens: { accessToken: 't' }, fetchJson: async () => emails });

    await expect(profileOf([{ email: 'x@example.com', primary: 'true', verified: 1 }])).resolves.toMatchObject({ email: undefined, emailVerified: false });
    await expect(profileOf([{ email: 'x@example.com', primary: true, verified: false }])).resolves.toMatchObject({ emailVerified: false });
    await expect(profileOf([null, { email: 'x@example.com', primary: true, verified: true }])).resolves.toMatchObject({
      email: 'x@example.com',
      emailVerified: true,
    });
    await expect(profileOf({ message: 'Bad credentials' })).resolves.toMatchObject({ emailVerified: false });
  });
});

export type { User };
