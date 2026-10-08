/**
 * `@Can()` on WebSocket messages behind the real authentication. The socket is the connection:
 * `client.user` keeps what the last authenticated message left, and a `@Public()` message leaves
 * it alone. Authorization asks for the user of each message instead (`userOf`), so a `@Public()`
 * message is a guest, whoever the socket last authenticated and whatever happened to that session.
 */
import type { IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { Module, type INestApplication } from '@nestjs/common';
import { WsAdapter } from '@nestjs/platform-ws';
import { SubscribeMessage, WebSocketGateway, type OnGatewayConnection } from '@nestjs/websockets';
import { AuthorizationEvents, AuthorizationModule, Can, Policy, type AuthorizationDeniedEvent } from '@nestjs/authorization';
import request from 'supertest';
import { WebSocket } from 'ws';
import { createApp } from './support/adapters.js';
import { AuthenticationStorage, Public, WsAuthenticator } from '../lib/index.js';
import { AuthController, AuthProvidersModule, PASSWORDS, UsersModule, authenticationModule, type User } from './fixtures.js';

@Policy()
class DraftPolicy {
  read(user: User | null) {
    return !!user?.roles.includes('editor');
  }
}

@WebSocketGateway({ path: '/drafts' })
class DraftsGateway implements OnGatewayConnection {
  constructor(private readonly wsAuth: WsAuthenticator) {}

  async handleConnection(client: WebSocket, request: IncomingMessage) {
    await this.wsAuth.authenticateConnection(client, request, { required: false });
  }

  @SubscribeMessage('read')
  @Can(DraftPolicy, 'read')
  read() {
    return { event: 'draft', data: 'Q3 plan' };
  }

  // No provider runs: the policy sees a guest, as `@CurrentUser()` would.
  @Public()
  @SubscribeMessage('peek')
  @Can(DraftPolicy, 'read')
  peek() {
    return { event: 'draft', data: 'Q3 plan' };
  }
}

@Module({
  imports: [authenticationModule(), AuthorizationModule.forRoot({ policies: [DraftPolicy] }), UsersModule, AuthProvidersModule],
  controllers: [AuthController],
  providers: [DraftsGateway],
})
class DraftsAppModule {}

describe('@Can() on ws messages, with @nestjs/authentication', () => {
  let app: INestApplication;
  let base: string;
  const sockets: WebSocket[] = [];
  const denials: AuthorizationDeniedEvent[] = [];

  const loginCookie = async (email: string) => {
    const res = await request(app.getHttpServer()).post('/auth/login').send({ email, password: PASSWORDS[email] }).expect(200);
    return (res.headers['set-cookie'] as unknown as string[])[0].split(';')[0];
  };

  /** A socket whose handshake carries `cookie`. `next()` resolves its replies in order. */
  const connect = async (cookie: string) => {
    const socket = new WebSocket(`${base}/drafts`, { headers: { cookie } });
    sockets.push(socket);
    const replies: unknown[] = [];
    const waiting: ((reply: unknown) => void)[] = [];
    socket.on('message', (raw) => {
      const reply = JSON.parse(String(raw));
      const waiter = waiting.shift();
      if (waiter) {
        waiter(reply);
      } else {
        replies.push(reply);
      }
    });
    await new Promise((resolve, reject) => socket.once('open', resolve).once('error', reject));

    const send = (event: string, data: unknown = {}) => socket.send(JSON.stringify({ event, data }));
    const next = () => (replies.length ? Promise.resolve(replies.shift()) : new Promise((resolve) => waiting.push(resolve)));
    return { send, next, ask: (event: string, data?: unknown) => (send(event, data), next()) };
  };
  const unauthorized = { event: 'exception', data: { status: 'error', message: 'Unauthorized', statusCode: 401 } };
  const unauthenticated = { event: 'exception', data: { ...unauthorized.data, code: 'missing_credentials' } };
  const draft = { event: 'draft', data: 'Q3 plan' };

  beforeAll(async () => {
    app = await createApp('express', DraftsAppModule, { setup: (a) => void a.useWebSocketAdapter(new WsAdapter(a)) });
    base = `ws://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
    app.get(AuthorizationEvents).events$.subscribe((event) => denials.push(event));
  });
  afterEach(() => {
    sockets.splice(0).forEach((socket) => socket.close());
    denials.length = 0;
  });
  afterAll(() => app.close());

  it('evaluates a @Public() @Can() message after a sign-out everywhere as a guest, with no protected message in between', async () => {
    const stolen = await loginCookie('alice@example.com'); // the copy someone else holds
    const own = await loginCookie('alice@example.com'); // Alice's browser
    const socket = await connect(stolen); // the handshake authenticates Alice
    expect(await socket.ask('read')).toEqual(draft);

    await request(app.getHttpServer()).post('/auth/logout-everywhere').set('Cookie', own).expect(204);
    expect(await socket.ask('peek')).toEqual(unauthorized);
    expect(denials).toEqual([
      expect.objectContaining({ policy: 'DraftPolicy', ability: 'read', reason: 'unauthenticated', user: null, handler: 'DraftsGateway.peek' }),
    ]);

    // A protected message is refused by authentication, before any policy runs.
    expect(await socket.ask('read')).toEqual(unauthenticated);
    expect(denials).toHaveLength(1);
  });

  it('evaluates concurrent public and protected messages on one socket each as its own', async () => {
    const socket = await connect(await loginCookie('alice@example.com'));
    const sessions = app.get(AuthenticationStorage).sessions;
    const getSession = sessions.getSession.bind(sessions);
    const slow = vi.spyOn(sessions, 'getSession').mockImplementationOnce(async (id) => {
      await sleep(40);
      return getSession(id);
    });

    try {
      socket.send('read'); // still validating the session...
      socket.send('peek', 'now'); // ...when this one is authorized
      expect(await socket.next()).toEqual(unauthorized);
      expect(await socket.next()).toEqual(draft);
      expect(slow).toHaveBeenCalledTimes(1);
      expect(denials).toEqual([expect.objectContaining({ user: null, handler: 'DraftsGateway.peek' })]);
    } finally {
      slow.mockRestore();
    }
  });
});
