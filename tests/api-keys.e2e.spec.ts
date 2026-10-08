/**
 * API keys in an app that also signs in with a session cookie and JWT bearer tokens, on Express
 * and Fastify: all three on one route, `@Authenticate({ providers })` keeping a route to keys or
 * away from them, `mfa: true` refusing keys, the challenges and errors, the key id in the
 * session, no events per request; then the same keys over GraphQL, WebSockets and TCP.
 */
import type { IncomingMessage } from 'node:http';
import type { AddressInfo, Server as NetServer } from 'node:net';
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import { Controller, Get, HttpCode, Injectable, Module, Post, type INestApplication } from '@nestjs/common';
import { GraphQLModule, Query, Resolver } from '@nestjs/graphql';
import { ClientProxyFactory, MessagePattern, Transport, type ClientProxy, type MicroserviceOptions } from '@nestjs/microservices';
import { WsAdapter } from '@nestjs/platform-ws';
import { SubscribeMessage, WebSocketGateway, type OnGatewayConnection } from '@nestjs/websockets';
import { lastValueFrom } from 'rxjs';
import request from 'supertest';
import { WebSocket } from 'ws';
import { adapters, createApp } from './support/adapters.js';
import {
  ApiKeyProvider,
  Authenticate,
  AuthenticationContext,
  AuthenticationEvents,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentSession,
  CurrentUser,
  JwtBearerProvider,
  Public,
  SessionCookieProvider,
  SignInService,
  TokenService,
  WsAuthenticator,
  type ApiKeyRecord,
  type AuthenticationEvent,
  type JwtClaims,
  type SessionRecord,
} from '../lib/index.js';

interface Customer {
  id: string;
}

const customer = (id: string | undefined): Customer | null => (id ? { id } : null);

@Injectable()
class SessionAuth extends SessionCookieProvider<Customer> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return customer(session.userId);
  }
}

@Injectable()
class JwtAuth extends JwtBearerProvider<Customer> {
  constructor(registry: AuthenticationRegistry) {
    super({ realm: 'store' });
    registry.registerProvider(this, { order: 1 });
  }
  validate(claims: JwtClaims) {
    return customer(claims.sub);
  }
}

/** The keys table: what the app stores is the id, the hash, the owner and the expiry. */
@Injectable()
class ApiKeysTable {
  readonly rows = new Map<string, { hash: string; userId: string; expiresAt?: Date }>();
}

/** After JwtAuth: a key reaches it because JwtAuth leaves tokens shaped like keys alone. */
@Injectable()
class ApiKeyAuth extends ApiKeyProvider<Customer> {
  constructor(
    private readonly apiKeysTable: ApiKeysTable,
    registry: AuthenticationRegistry,
  ) {
    super({ prefix: 'cat', realm: 'store' });
    registry.registerProvider(this, { order: 2 });
  }
  findKey(id: string): ApiKeyRecord<Customer> | null {
    const row = this.apiKeysTable.rows.get(id);
    return row ? { hash: row.hash, user: { id: row.userId }, expiresAt: row.expiresAt } : null;
  }
}

@Controller()
class StoreController {
  constructor(
    private readonly signInService: SignInService,
    private readonly tokenService: TokenService,
    private readonly apiKeyAuth: ApiKeyAuth,
    private readonly apiKeysTable: ApiKeysTable,
    private readonly authenticationContext: AuthenticationContext,
  ) {}

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn() {
    await this.signInService.signIn('ada', { method: 'password' });
  }

  @Public()
  @Post('token')
  @HttpCode(200)
  token() {
    return this.tokenService.issue('ada', { method: 'password', claims: { amr: ['pwd'] } });
  }

  // Keys are made from a browser session only: a leaked key can't mint more.
  @Authenticate({ providers: [SessionCookieProvider] })
  @Post('api-keys')
  create(@CurrentUser('id') userId: string) {
    const { key, id, hash } = this.apiKeyAuth.generate();
    this.apiKeysTable.rows.set(id, { hash, userId });
    return { id, key };
  }

  @Get('me')
  me(@CurrentUser('id') id: string, @CurrentSession() session: object) {
    return { id, session, contextSession: this.authenticationContext.session };
  }

  @Authenticate({ mfa: true })
  @Get('me/step-up')
  stepUp(@CurrentUser('id') id: string) {
    return { id };
  }

  @Authenticate({ providers: [ApiKeyProvider] })
  @Post('bulk-orders')
  @HttpCode(200)
  bulkOrders(@CurrentUser('id') id: string, @CurrentSession() session: { keyId: string }) {
    return { id, keyId: session.keyId };
  }

  @Authenticate({ providers: [SessionCookieProvider, JwtBearerProvider] })
  @Get('account')
  account(@CurrentUser('id') id: string) {
    return { id };
  }

  @MessagePattern('whoami')
  whoamiOverRpc(@CurrentUser('id') id: string) {
    return id;
  }
}

@Resolver()
class ViewerResolver {
  @Query(() => String)
  viewer(@CurrentUser('id') id: string, @CurrentSession() session: { keyId: string }) {
    return `${id} ${session.keyId}`;
  }
}

@WebSocketGateway({ path: '/ws' })
class OrdersGateway implements OnGatewayConnection {
  constructor(private readonly wsAuthenticator: WsAuthenticator) {}

  handleConnection(client: WebSocket, request: IncomingMessage) {
    return this.wsAuthenticator.authenticateConnection(client, request);
  }

  @SubscribeMessage('whoami')
  whoami(@CurrentUser('id') id: string, @CurrentSession() session: { keyId: string }) {
    return { event: 'whoami', data: { id, keyId: session.keyId } };
  }
}

const authentication = AuthenticationModule.forRoot({
  session: { cookie: { secure: false } }, // supertest talks plain HTTP
  accessToken: { key: 'test-secret-that-is-at-least-32-bytes-long!', issuer: 'https://store.test', audience: 'mobile-app' },
});

@Module({
  imports: [authentication],
  controllers: [StoreController],
  providers: [SessionAuth, JwtAuth, ApiKeysTable, ApiKeyAuth],
})
class StoreModule {}

@Module({
  imports: [
    authentication,
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
      context: ({ req }: { req: unknown }) => ({ req }),
    }),
  ],
  controllers: [StoreController],
  providers: [SessionAuth, JwtAuth, ApiKeysTable, ApiKeyAuth, ViewerResolver, OrdersGateway],
})
class HybridStoreModule {}

const cookieOf = (res: request.Response) => ([] as string[]).concat(res.headers['set-cookie'] ?? [])[0].split(';')[0];

describe.each(adapters.map((a) => a.name))('API keys next to cookies and bearer tokens (%s)', (adapter) => {
  let app: INestApplication;
  let cookie: string;
  let accessToken: string;
  let key: string;
  let keyId: string;
  const http = () => request(app.getHttpServer());
  const withKey = (token = key) => ({ Authorization: `Bearer ${token}` });

  beforeAll(async () => {
    app = await createApp(adapter, StoreModule);
    cookie = cookieOf(await http().post('/sign-in').expect(200));
    accessToken = (await http().post('/token').expect(200)).body.accessToken;
    const created = await http().post('/api-keys').set('Cookie', cookie).expect(201);
    ({ key, id: keyId } = created.body);
    expect(key).toMatch(/^cat_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
  });
  afterAll(() => app.close());

  it('signs the same customer in with a session cookie, a JWT or a key, on one route', async () => {
    const viaCookie = await http().get('/me').set('Cookie', cookie).expect(200);
    expect(viaCookie.body).toMatchObject({ id: 'ada', session: { userId: 'ada' } });

    const viaJwt = await http().get('/me').set('Authorization', `Bearer ${accessToken}`).expect(200);
    expect(viaJwt.body).toMatchObject({ id: 'ada', session: { sub: 'ada', amr: ['pwd'] } });

    const viaKey = await http().get('/me').set(withKey()).expect(200);
    const session = { method: 'api-key', keyId };
    expect(viaKey.body).toEqual({ id: 'ada', session, contextSession: session });
  });

  it('keeps a route to keys, or away from them, with @Authenticate({ providers })', async () => {
    await http().post('/bulk-orders').set(withKey()).expect(200, { id: 'ada', keyId });
    await http().post('/bulk-orders').set('Cookie', cookie).expect(401);
    await http().post('/bulk-orders').set('Authorization', `Bearer ${accessToken}`).expect(401);

    await http().get('/account').set('Cookie', cookie).expect(200, { id: 'ada' });
    await http().get('/account').set('Authorization', `Bearer ${accessToken}`).expect(200, { id: 'ada' });
    const refused = await http().get('/account').set(withKey()).expect(401);
    expect(refused.headers['www-authenticate']).toBe('Bearer realm="store"');

    // A key can't make keys.
    await http().post('/api-keys').set(withKey()).expect(401);
  });

  it('never counts a key as a second factor', async () => {
    const res = await http().get('/me/step-up').set(withKey()).expect(401);
    expect(res.body).toEqual({ statusCode: 401, error: 'mfa_required', errorCode: 'mfa_required', message: 'Second factor required' });
  });

  it('answers a bad key with an RFC 6750 invalid_token challenge, and no credentials with one challenge per realm', async () => {
    const wrong = `${key.slice(0, -43)}${'A'.repeat(43)}`;
    const refused = await http().get('/me').set(withKey(wrong)).expect(401);
    expect(refused.headers['www-authenticate']).toBe('Bearer realm="store", error="invalid_token", error_description="invalid api key"');
    expect(refused.body).toMatchObject({ statusCode: 401, message: 'invalid api key' });

    const table = app.get(ApiKeysTable);
    table.rows.set(keyId, { ...table.rows.get(keyId)!, expiresAt: new Date(Date.now() - 1) });
    try {
      const expired = await http().get('/me').set(withKey()).expect(401);
      expect(expired.headers['www-authenticate']).toContain('error_description="api key expired"');
    } finally {
      delete table.rows.get(keyId)!.expiresAt;
    }

    // JwtAuth and ApiKeyAuth both accept `Bearer realm="store"`: it's sent once.
    const anonymous = await http().get('/me').expect(401);
    expect(anonymous.headers['www-authenticate']).toBe('Bearer realm="store"');
  });

  it('stops a revoked key at once', async () => {
    const created = await http().post('/api-keys').set('Cookie', cookie).expect(201);
    await http().get('/me').set(withKey(created.body.key)).expect(200);
    app.get(ApiKeysTable).rows.delete(created.body.id);
    await http().get('/me').set(withKey(created.body.key)).expect(401);
  });

  it('emits no event per request: a key is a credential, not a sign-in', async () => {
    const events: AuthenticationEvent[] = [];
    const subscription = app.get(AuthenticationEvents).events$.subscribe((event) => events.push(event));
    try {
      await http().get('/me').set(withKey()).expect(200);
      await http().get('/me').set(withKey(`${key.slice(0, -43)}${'A'.repeat(43)}`)).expect(401);
      expect(events).toEqual([]);
    } finally {
      subscription.unsubscribe();
    }
  });
});

describe('API keys over GraphQL, WebSockets and TCP (express)', () => {
  let app: INestApplication;
  let client: ClientProxy;
  let wsUrl: string;
  let key: string;
  let keyId: string;

  /** Opens a socket with these headers, sends one message, and resolves with the reply or the close code. */
  async function ask(headers: Record<string, string>) {
    const socket = new WebSocket(wsUrl, { headers });
    const closed = new Promise<{ code: number }>((resolve) => socket.once('close', (code) => resolve({ code })));
    const reply = new Promise<unknown>((resolve) => socket.once('message', (raw) => resolve(JSON.parse(raw.toString()))));
    await new Promise((resolve, reject) => socket.once('open', resolve).once('error', reject));
    socket.send(JSON.stringify({ event: 'whoami', data: {} }));
    try {
      return await Promise.race([reply, closed]);
    } finally {
      socket.close();
    }
  }

  beforeAll(async () => {
    app = await createApp('express', HybridStoreModule, {
      setup: async (created) => {
        created.useWebSocketAdapter(new WsAdapter(created));
        created.connectMicroservice<MicroserviceOptions>(
          { transport: Transport.TCP, options: { host: '127.0.0.1', port: 0 } },
          { inheritAppConfig: true },
        );
        await created.startAllMicroservices();
      },
    });
    wsUrl = `ws://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}/ws`;
    const [microservice] = app.getMicroservices();
    const { port } = microservice.unwrap<NetServer>().address() as AddressInfo;
    client = ClientProxyFactory.create({ transport: Transport.TCP, options: { host: '127.0.0.1', port } });
    await client.connect();

    const cookie = cookieOf(await request(app.getHttpServer()).post('/sign-in').expect(200));
    ({ key, id: keyId } = (await request(app.getHttpServer()).post('/api-keys').set('Cookie', cookie).expect(201)).body);
  });
  afterAll(async () => {
    await client?.close();
    await app?.close();
  });

  it('authenticates GraphQL operations from context.req', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${key}`)
      .send({ query: '{ viewer }' })
      .expect(200);
    expect(res.body).toEqual({ data: { viewer: `ada ${keyId}` } });

    const refused = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${key.slice(0, -43)}${'A'.repeat(43)}`)
      .send({ query: '{ viewer }' });
    expect(refused.body.errors[0]).toMatchObject({ message: 'invalid api key', extensions: { code: 'UNAUTHENTICATED' } });
  });

  it('authenticates a WebSocket connection from the upgrade request', async () => {
    expect(await ask({ authorization: `Bearer ${key}` })).toEqual({ event: 'whoami', data: { id: 'ada', keyId } });
    expect(await ask({ authorization: `Bearer ${key.slice(0, -43)}${'A'.repeat(43)}` })).toEqual({ code: 1008 });
  });

  it('finds no key in an RPC message: microservice callers authenticate with a provider of their own', async () => {
    const outcome = await lastValueFrom(client.send('whoami', { authorization: `Bearer ${key}` })).then(
      (reply: unknown) => ({ reply }),
      (error: unknown) => ({ error }),
    );
    expect(outcome).toEqual({ error: { statusCode: 401, message: 'Unauthorized', errorCode: 'missing_credentials' } });
  });
});
