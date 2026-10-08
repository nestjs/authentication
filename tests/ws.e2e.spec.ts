import type { IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { Logger, Module, type INestApplication } from '@nestjs/common';
import { WsAdapter } from '@nestjs/platform-ws';
import { ConnectedSocket, MessageBody, SubscribeMessage, WebSocketGateway, type OnGatewayConnection } from '@nestjs/websockets';
import request from 'supertest';
import { WebSocket } from 'ws';
import { adapters, createApp } from './support/adapters.js';
import { AuthenticationContext, AuthenticationStorage, CurrentUser, Public, WsAuthenticator } from '../lib/index.js';
import { ApiKeysModule, AuthProvidersModule, AuthController, PASSWORDS, authenticationModule, UsersModule, type User } from './fixtures.js';

@WebSocketGateway({ path: '/ws' })
class ChatGateway implements OnGatewayConnection {
  constructor(
    private readonly wsAuth: WsAuthenticator,
    private readonly auth: AuthenticationContext,
  ) {}

  async handleConnection(client: WebSocket, request: IncomingMessage) {
    // Anonymous connections are allowed here; messages decide.
    await this.wsAuth.authenticateConnection(client, request, { required: false });
  }

  @SubscribeMessage('whoami')
  whoami(@CurrentUser() user: User | null) {
    return { event: 'whoami', data: { param: user?.id ?? null, context: this.auth.user?.id ?? null } };
  }

  @Public()
  @SubscribeMessage('ping')
  ping() {
    return { event: 'pong', data: { context: this.auth.user } };
  }

  // What each reader sees on a public message: the param, the context, and the socket's copy.
  @Public()
  @SubscribeMessage('public-who')
  publicWho(@CurrentUser() user: User | null, @ConnectedSocket() client: WebSocket & { user?: User | null }) {
    return { event: 'public-who', data: { param: user?.id ?? null, context: this.auth.user?.id ?? null, connection: client.user?.id ?? null } };
  }

  // requireUser() under a public message: an AuthenticationError, answered as a ws 401.
  @Public()
  @SubscribeMessage('mine')
  mine() {
    return { event: 'mine', data: this.auth.requireUser().id };
  }

  @SubscribeMessage('slow')
  async slow(@MessageBody() body: { delay: number; tag: string }) {
    await sleep(body.delay);
    return { event: 'slow', data: { tag: body.tag, context: this.auth.user?.id } };
  }
}

@WebSocketGateway({ path: '/ws-strict' })
class StrictGateway implements OnGatewayConnection {
  constructor(private readonly wsAuth: WsAuthenticator) {}
  handleConnection(client: WebSocket, request: IncomingMessage) {
    return this.wsAuth.authenticateConnection(client, request);
  }
  @SubscribeMessage('whoami')
  whoami(@CurrentUser('id') id: string) {
    return { event: 'whoami', data: id };
  }
}

@Module({
  imports: [authenticationModule(), UsersModule, AuthProvidersModule, ApiKeysModule],
  controllers: [AuthController],
  providers: [ChatGateway, StrictGateway],
})
class WsAppModule {}

class Client {
  private readonly inbox: { event: string; data: any }[] = [];
  private readonly waiters: (() => void)[] = [];
  closed?: { code: number; reason: string };

  constructor(readonly socket: WebSocket) {
    socket.on('message', (raw) => {
      this.inbox.push(JSON.parse(raw.toString()));
      this.waiters.splice(0).forEach((w) => w());
    });
    socket.on('close', (code, reason) => {
      this.closed = { code, reason: reason.toString() };
      this.waiters.splice(0).forEach((w) => w());
    });
  }

  static async connect(url: string, headers: Record<string, string> = {}) {
    const socket = new WebSocket(url, { headers });
    const client = new Client(socket);
    await new Promise((resolve, reject) => socket.once('open', resolve).once('error', reject));
    return client;
  }

  send(event: string, data: unknown = {}) {
    this.socket.send(JSON.stringify({ event, data }));
  }

  async next(): Promise<{ event: string; data: any }> {
    while (!this.inbox.length) {
      if (this.closed) {
        throw new Error(`closed ${this.closed.code}`);
      }
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    return this.inbox.shift()!;
  }

  async request(event: string, data: unknown = {}) {
    this.send(event, data);
    return this.next();
  }

  async waitClose() {
    while (!this.closed) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    return this.closed;
  }

  close() {
    this.socket.close();
  }
}

describe.each(adapters.map((a) => a.name))('WebSocket gateway on platform-ws (%s)', (adapter) => {
  let app: INestApplication;
  let base: string;
  const clients: Client[] = [];
  const connect = async (path: string, headers?: Record<string, string>) => {
    const client = await Client.connect(`${base}${path}`, headers);
    clients.push(client);
    return client;
  };
  const loginCookie = async (email: string) => {
    const res = await request(app.getHttpServer()).post('/auth/login').send({ email, password: PASSWORDS[email] }).expect(200);
    return (res.headers['set-cookie'] as unknown as string[])[0].split(';')[0];
  };

  beforeAll(async () => {
    app = await createApp(adapter, WsAppModule, { setup: (a) => void a.useWebSocketAdapter(new WsAdapter(a)) });
    base = `ws://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
  });
  afterEach(() => clients.splice(0).forEach((c) => c.close()));
  afterAll(() => app.close());

  it('authenticates messages from the handshake cookie; AuthenticationContext works in the handler', async () => {
    const client = await connect('/ws', { cookie: await loginCookie('bob@example.com') });
    expect(await client.request('whoami')).toEqual({ event: 'whoami', data: { param: 'u2', context: 'u2' } });
  });

  it('authenticates a bearer token from the handshake headers', async () => {
    const client = await connect('/ws', { 'x-api-key': 'key-ci' });
    expect((await client.request('whoami')).data).toEqual({ param: 'svc-ci', context: 'svc-ci' });
  });

  it('answers anonymous messages with a ws exception, not a leaked HTTP error', async () => {
    const client = await connect('/ws');
    expect(await client.request('whoami')).toEqual({
      event: 'exception',
      data: { status: 'error', statusCode: 401, message: 'Unauthorized', errorCode: 'missing_credentials' },
    });

    expect(await client.request('ping')).toEqual({ event: 'pong', data: { context: null } });

    expect(await client.request('mine')).toEqual({
      event: 'exception',
      data: { status: 'error', statusCode: 401, message: 'Unauthorized' },
    });
  });

  it('re-authenticates every message: a revoked session stops working mid-connection', async () => {
    const cookie = await loginCookie('bob@example.com');
    const client = await connect('/ws', { cookie });
    expect((await client.request('whoami')).data.param).toBe('u2');

    await request(app.getHttpServer()).post('/auth/logout').set('Cookie', cookie).expect(204);
    expect((await client.request('whoami')).event).toBe('exception');
  });

  it('gives a @Public() message no user, and a protected one its own, whatever the payload', async () => {
    const client = await connect('/ws', { cookie: await loginCookie('bob@example.com') });
    // A primitive payload shares nothing with the guard but the socket, which outlives the message.
    for (const payload of ['hi', 42, {}]) {
      expect((await client.request('public-who', payload)).data).toMatchObject({ param: null, context: null });
      expect((await client.request('whoami', payload)).data).toEqual({ param: 'u2', context: 'u2' });
    }
  });

  it('forgets the connection’s user once a message is refused for its credentials (a revoked session)', async () => {
    const cookie = await loginCookie('bob@example.com');
    const client = await connect('/ws', { cookie });
    expect((await client.request('public-who', 'hi')).data.connection).toBe('u2'); // recorded at the handshake

    await request(app.getHttpServer()).post('/auth/logout').set('Cookie', cookie).expect(204);
    expect((await client.request('whoami', 'hi')).event).toBe('exception');
    // Code that reads `client.user` on public messages sees nobody now.
    expect((await client.request('public-who', 'hi')).data).toEqual({ param: null, context: null, connection: null });
  });

  it('keeps per-message context separate for concurrent messages on different sockets', async () => {
    const bob = await connect('/ws', { cookie: await loginCookie('bob@example.com') });
    const ci = await connect('/ws', { 'x-api-key': 'key-ci' });

    bob.send('slow', { delay: 40, tag: 'bob' });
    ci.send('slow', { delay: 5, tag: 'ci' });

    expect((await ci.next()).data).toEqual({ tag: 'ci', context: 'svc-ci' });
    expect((await bob.next()).data).toEqual({ tag: 'bob', context: 'u2' });
  });

  it('ignores the session cookie on a handshake from another origin (cross-site WebSocket hijacking)', async () => {
    const cookie = await loginCookie('bob@example.com');
    const hijacked = await connect('/ws-strict', { cookie, origin: 'https://evil.test' });
    expect(await hijacked.waitClose()).toEqual({ code: 1008, reason: 'Unauthorized' });

    const own = await connect('/ws', { cookie, origin: base.replace('ws:', 'http:') });
    expect((await own.request('whoami')).data.param).toBe('u2');
  });

  it('closes the connection with 1011 when a store fails during the handshake, instead of an unhandled rejection', async () => {
    const cookie = await loginCookie('bob@example.com');
    const failure = new Error('session store down');
    const get = vi.spyOn(app.get(AuthenticationStorage).sessions, 'getSession').mockRejectedValueOnce(failure);
    const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);

    try {
      const client = await connect('/ws-strict', { cookie });
      expect(await client.waitClose()).toEqual({ code: 1011, reason: 'Internal Error' });
      expect(logged).toHaveBeenCalledWith('Authenticating a WebSocket connection failed', failure.stack);
    } finally {
      get.mockRestore();
      logged.mockRestore();
    }
  });

  it('closes unauthenticated connections to a strict gateway with 1008', async () => {
    const anonymous = await connect('/ws-strict');
    expect(await anonymous.waitClose()).toEqual({ code: 1008, reason: 'Unauthorized' });

    const ci = await connect('/ws-strict', { 'x-api-key': 'key-ci' });
    expect(await ci.request('whoami')).toEqual({ event: 'whoami', data: 'svc-ci' });
  });
});
