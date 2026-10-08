/**
 * One hybrid app on Express and Fastify, serving HTTP, WebSockets (`@nestjs/platform-ws`) and a
 * TCP microservice: the route options that the transport-specific suites leave out
 * (`verifiedEmail`, `mfa`, `providers`) and the package's errors thrown by handlers, as each
 * transport's client receives them. Sessions come from a real password-less sign-in over HTTP.
 */
import type { IncomingMessage } from 'node:http';
import type { AddressInfo, Server as NetServer } from 'node:net';
import { Body, Controller, HttpCode, Injectable, Module, Post, type ExecutionContext, type INestApplication } from '@nestjs/common';
import { ClientProxyFactory, MessagePattern, Transport, type ClientProxy, type MicroserviceOptions } from '@nestjs/microservices';
import { WsAdapter } from '@nestjs/platform-ws';
import { SubscribeMessage, WebSocketGateway, type OnGatewayConnection } from '@nestjs/websockets';
import request from 'supertest';
import { lastValueFrom } from 'rxjs';
import { WebSocket } from 'ws';
import { adapters, createApp } from './support/adapters.js';
import {
  Authenticate,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentUser,
  MfaAlreadyEnrolledError,
  MfaService,
  Public,
  SessionCookieProvider,
  SignInService,
  WsAuthenticator,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';

interface Person {
  id: string;
  emailVerified: boolean;
}

const person = (id: string): Person => ({ id, emailVerified: id.startsWith('verified') });
const totp = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(Date.now() / 30_000) + offset);

@Injectable()
class SessionAuth extends SessionCookieProvider<Person> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return person(session.userId);
  }
}

/** Services name themselves: `x-service` on HTTP and ws, `service` in RPC payloads. */
@Injectable()
class ServiceAuth extends AuthenticationProvider<Person> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this, { order: 1 });
  }
  authenticate(context: ExecutionContext) {
    const id = context.getType() === 'rpc' ? context.switchToRpc().getData()?.service : this.header(context, 'x-service');
    return id ? { user: person(id) } : null;
  }
}

@Controller()
class SignInController {
  constructor(
    private readonly signInService: SignInService,
    private readonly mfaService: MfaService,
  ) {}

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn(@Body('userId') userId: string) {
    await this.signInService.signIn(userId, { method: 'password' });
  }

  @Public()
  @Post('test/enroll')
  async enroll(@Body('userId') userId: string) {
    const { secret } = await this.mfaService.enroll(userId, `${userId}@example.com`);
    await this.mfaService.confirm(userId, totp(secret, -1));
    return { secret };
  }

  @Public()
  @Post('mfa')
  @HttpCode(200)
  async completeMfa(@Body('code') code: string) {
    await this.signInService.completeMfa({ code });
  }

  @MessagePattern('orders')
  @Authenticate({ verifiedEmail: true })
  orders(@CurrentUser('id') id: string) {
    return { orders: [], for: id };
  }

  @MessagePattern('enroll')
  enrollOverRpc(@CurrentUser('id') id: string) {
    throw new MfaAlreadyEnrolledError(id);
  }
}

@WebSocketGateway({ path: '/ws' })
class AccountGateway implements OnGatewayConnection {
  constructor(private readonly wsAuthenticator: WsAuthenticator) {}

  async handleConnection(client: WebSocket, request: IncomingMessage) {
    await this.wsAuthenticator.authenticateConnection(client, request, { required: false });
  }

  @SubscribeMessage('whoami')
  whoami(@CurrentUser('id') id: string) {
    return { event: 'whoami', data: id };
  }

  @Authenticate({ verifiedEmail: true })
  @SubscribeMessage('orders')
  orders(@CurrentUser('id') id: string) {
    return { event: 'orders', data: id };
  }

  @Authenticate({ mfa: true })
  @SubscribeMessage('admin')
  admin() {
    return { event: 'admin', data: 'ok' };
  }

  @Authenticate({ providers: [SessionCookieProvider] })
  @SubscribeMessage('browser-only')
  browserOnly(@CurrentUser('id') id: string) {
    return { event: 'browser-only', data: id };
  }

  @SubscribeMessage('enroll')
  enroll(@CurrentUser('id') id: string) {
    throw new MfaAlreadyEnrolledError(id);
  }
}

@Module({
  imports: [AuthenticationModule.forRoot({ mfa: { encryption: false } })],
  controllers: [SignInController],
  providers: [SessionAuth, ServiceAuth, AccountGateway],
})
class HybridAppModule {}

/** Sends one message and resolves with the first reply. */
async function ask(url: string, headers: Record<string, string>, event: string) {
  const socket = new WebSocket(url, { headers });
  await new Promise((resolve, reject) => socket.once('open', resolve).once('error', reject));
  const reply = new Promise<{ event: string; data: unknown }>((resolve) => socket.once('message', (raw) => resolve(JSON.parse(raw.toString()))));
  socket.send(JSON.stringify({ event, data: {} }));
  try {
    return await reply;
  } finally {
    socket.close();
  }
}

describe.each(adapters.map((a) => a.name))('one hybrid app: HTTP, WebSockets and TCP (%s)', (adapter) => {
  let app: INestApplication;
  let client: ClientProxy;
  let wsUrl: string;
  const http = () => request(app.getHttpServer());
  const signIn = async (userId: string) => {
    const res = await http().post('/sign-in').send({ userId }).expect(200);
    return ([] as string[]).concat(res.headers['set-cookie'] ?? [])[0].split(';')[0];
  };
  const send = (pattern: string, data: object) =>
    lastValueFrom(client.send(pattern, data)).then(
      (reply: unknown) => ({ reply }),
      (error: unknown) => ({ error }),
    );

  beforeAll(async () => {
    app = await createApp(adapter, HybridAppModule, {
      setup: async (created) => {
        created.useWebSocketAdapter(new WsAdapter(created));
        // A hybrid app's microservice runs the app's global guards and interceptors (the module's
        // APP_GUARD and APP_INTERCEPTOR included) only with `inheritAppConfig`.
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
  });
  afterAll(async () => {
    await client?.close();
    await app?.close();
  });

  it('refuses an unverified address with 403 email_unverified over WebSockets and TCP', async () => {
    const unverified = await signIn('ada');
    expect(await ask(wsUrl, { cookie: unverified }, 'orders')).toEqual({
      event: 'exception',
      data: { status: 'error', statusCode: 403, error: 'email_unverified', errorCode: 'email_unverified', message: 'Email address not verified' },
    });
    expect(await ask(wsUrl, { cookie: await signIn('verified-grace') }, 'orders')).toEqual({ event: 'orders', data: 'verified-grace' });

    expect(await send('orders', { service: 'billing' })).toEqual({
      error: { statusCode: 403, error: 'email_unverified', errorCode: 'email_unverified', message: 'Email address not verified' },
    });
    expect(await send('orders', { service: 'verified-billing' })).toEqual({ reply: { orders: [], for: 'verified-billing' } });
    expect(await send('orders', {})).toEqual({ error: { statusCode: 401, message: 'Unauthorized', errorCode: 'missing_credentials' } });
  });

  it('asks a WebSocket handshake with a pending session, and a step-up handler, for the second factor', async () => {
    const userId = `mfa-${adapter}`;
    const { secret } = (await http().post('/test/enroll').send({ userId }).expect(201)).body;
    const pending = await signIn(userId);
    const mfaRequired = { event: 'exception', data: { status: 'error', statusCode: 401, error: 'mfa_required', errorCode: 'mfa_required', message: 'Second factor required' } };

    expect(await ask(wsUrl, { cookie: pending }, 'whoami')).toEqual(mfaRequired);
    expect(await ask(wsUrl, { cookie: await signIn('password-only') }, 'admin')).toEqual(mfaRequired);

    const completed = await http().post('/mfa').set('Cookie', pending).send({ code: totp(secret) }).expect(200);
    const verified = ([] as string[]).concat(completed.headers['set-cookie'] ?? [])[0].split(';')[0];
    expect(await ask(wsUrl, { cookie: verified }, 'admin')).toEqual({ event: 'admin', data: 'ok' });
  });

  it('keeps a WebSocket handler to the providers it names: other credentials count as none', async () => {
    expect(await ask(wsUrl, { 'x-service': 'billing' }, 'whoami')).toEqual({ event: 'whoami', data: 'billing' });
    expect(await ask(wsUrl, { 'x-service': 'billing' }, 'browser-only')).toEqual({
      event: 'exception',
      data: { status: 'error', statusCode: 401, message: 'Unauthorized', errorCode: 'missing_credentials' },
    });
    expect(await ask(wsUrl, { cookie: await signIn('ada') }, 'browser-only')).toEqual({ event: 'browser-only', data: 'ada' });
  });

  it('answers MfaAlreadyEnrolledError thrown by a handler with a 409 on each transport', async () => {
    expect(await ask(wsUrl, { 'x-service': 'billing' }, 'enroll')).toEqual({
      event: 'exception',
      data: { status: 'error', statusCode: 409, message: 'Authenticator already enrolled' },
    });
    expect(await send('enroll', { service: 'billing' })).toEqual({ error: { statusCode: 409, message: 'Authenticator already enrolled' } });
  });
});
