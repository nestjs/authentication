/**
 * A microservice over TCP (a real transport): the global guard on message handlers,
 * `@CurrentUser()`, `@CurrentSession()` and `AuthenticationContext` in them, and the errors a
 * client receives for each refusal: the guard's, a provider's, and those thrown by handlers.
 */
import type { AddressInfo, Server as NetServer } from 'node:net';
import { Controller, Injectable, Module, type ExecutionContext, type INestMicroservice } from '@nestjs/common';
import { ClientProxyFactory, MessagePattern, Payload, Transport, type ClientProxy } from '@nestjs/microservices';
import { Test } from '@nestjs/testing';
import { lastValueFrom } from 'rxjs';
import {
  Authenticate,
  AuthenticationContext,
  AuthenticationError,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentSession,
  CurrentUser,
  MfaAlreadyEnrolledError,
  Public,
  RefreshTokenError,
  type AuthenticationResult,
} from '../lib/index.js';

type Caller = { id: string; roles: string[] };

const calls: string[] = [];

/** Service-to-service calls carry a token in the payload; the producer writes it. */
@Injectable()
class PayloadTokenAuth extends AuthenticationProvider<Caller, { tokenId: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }

  authenticate(context: ExecutionContext): AuthenticationResult<Caller, { tokenId: string }> | null {
    const token = context.switchToRpc().getData()?.token;
    calls.push(String(token));
    switch (token) {
      case undefined:
        return null;
      case 'revoked':
        throw new AuthenticationError('Token revoked', { code: 'token_revoked' });
      case 'pending':
        return { user: { id: 'svc-pending', roles: [] }, mfa: 'pending' };
      case 'strong':
        return { user: { id: 'svc-strong', roles: ['admin'] }, session: { tokenId: 't-strong' }, mfa: 'verified' };
      default:
        return { user: { id: `svc-${token}`, roles: ['worker'] }, session: { tokenId: `t-${token}` } };
    }
  }
}

@Injectable()
class Rendezvous {
  private arrived = 0;
  private release!: () => void;
  private readonly gate = new Promise<void>((resolve) => (this.release = resolve));

  constructor(private readonly auth: AuthenticationContext<Caller>) {}

  /** The first caller waits for the second: both handlers are in flight at once. */
  async meet() {
    const before = this.auth.user?.id;
    this.arrived++;
    if (this.arrived === 2) {
      this.release();
    }
    await this.gate;
    return { before, after: this.auth.user?.id };
  }
}

@Controller()
class JobsController {
  constructor(
    private readonly auth: AuthenticationContext<Caller, { tokenId: string }>,
    private readonly rendezvous: Rendezvous,
  ) {}

  @MessagePattern('whoami')
  whoami(@CurrentUser() user: Caller, @CurrentUser('id' as never) id: string, @CurrentSession() session: unknown) {
    return { user, id, session, fromContext: this.auth.user?.id, sessionFromContext: this.auth.session };
  }

  @MessagePattern('feed')
  @Authenticate({ optional: true })
  feed(@CurrentUser() user: Caller | null) {
    return { for: user?.id ?? null };
  }

  @MessagePattern('mine')
  @Authenticate({ optional: true })
  mine() {
    return { id: this.auth.requireUser().id };
  }

  @MessagePattern('health')
  @Public()
  health(@CurrentUser() user: unknown) {
    return { ok: true, user };
  }

  @MessagePattern('admin')
  @Authenticate({ mfa: true })
  admin(@Payload() data: { action: string }) {
    return { done: data.action };
  }

  @MessagePattern('enroll')
  enroll(@CurrentUser('id' as never) id: string) {
    throw new MfaAlreadyEnrolledError(id);
  }

  @MessagePattern('refresh')
  refresh() {
    throw new RefreshTokenError('reused');
  }

  @MessagePattern('meet')
  meet() {
    return this.rendezvous.meet();
  }
}

@Module({
  imports: [AuthenticationModule.forRoot({})],
  controllers: [JobsController],
  providers: [PayloadTokenAuth, Rendezvous],
})
class JobsModule {}

describe('microservice over TCP', () => {
  let app: INestMicroservice;
  let client: ClientProxy;
  const send = (pattern: string, data: object = {}) =>
    lastValueFrom(client.send(pattern, data)).then(
      (reply: unknown) => ({ reply }),
      (error: unknown) => ({ error }),
    );

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [JobsModule] }).compile();
    app = moduleRef.createNestMicroservice({ transport: Transport.TCP, options: { host: '127.0.0.1', port: 0 } });
    app.useLogger(false);
    await app.listen();

    const { port } = app.unwrap<NetServer>().address() as AddressInfo;
    client = ClientProxyFactory.create({ transport: Transport.TCP, options: { host: '127.0.0.1', port } });
    await client.connect();
  });
  afterAll(async () => {
    await client.close();
    await app.close();
  });
  beforeEach(() => {
    calls.length = 0;
  });

  it('gives the handler the caller through @CurrentUser(), @CurrentSession() and AuthenticationContext', async () => {
    expect(await send('whoami', { token: 'billing' })).toEqual({
      reply: {
        user: { id: 'svc-billing', roles: ['worker'] },
        id: 'svc-billing',
        session: { tokenId: 't-billing' },
        fromContext: 'svc-billing',
        sessionFromContext: { tokenId: 't-billing' },
      },
    });
  });

  it('answers an anonymous message with a 401, in the shape the client can read', async () => {
    expect(await send('whoami')).toEqual({ error: { statusCode: 401, message: 'Unauthorized', errorCode: 'missing_credentials' } });
  });

  it('passes a provider’s refusal through with its message and code', async () => {
    expect(await send('whoami', { token: 'revoked' })).toEqual({
      error: { statusCode: 401, error: 'token_revoked', message: 'Token revoked', errorCode: 'token_revoked' },
    });
    expect(await send('feed', { token: 'revoked' })).toEqual({
      error: { statusCode: 401, error: 'token_revoked', message: 'Token revoked', errorCode: 'token_revoked' },
    });
  });

  it('lets anonymous callers through optional handlers, but not requireUser() in them', async () => {
    expect(await send('feed')).toEqual({ reply: { for: null } });
    expect(await send('feed', { token: 'billing' })).toEqual({ reply: { for: 'svc-billing' } });
    expect(await send('mine')).toEqual({ error: { statusCode: 401, message: 'Unauthorized' } });
    expect(await send('mine', { token: 'billing' })).toEqual({ reply: { id: 'svc-billing' } });
  });

  it('never runs providers for @Public() handlers', async () => {
    expect(await send('health', { token: 'revoked' })).toEqual({ reply: { ok: true, user: null } });
    expect(calls).toEqual([]);
  });

  it('asks for a second factor: pending callers are anonymous, and `mfa: true` needs a verified one', async () => {
    const mfaRequired = { error: { statusCode: 401, error: 'mfa_required', errorCode: 'mfa_required', message: 'Second factor required' } };
    expect(await send('whoami', { token: 'pending' })).toEqual(mfaRequired);
    expect(await send('feed', { token: 'pending' })).toEqual({ reply: { for: null } });
    expect(await send('admin', { token: 'billing', action: 'purge' })).toEqual(mfaRequired);
    expect(await send('admin', { token: 'strong', action: 'purge' })).toEqual({ reply: { done: 'purge' } });
  });

  it('turns the package’s errors thrown by handlers into the client’s 401 and 409', async () => {
    expect(await send('refresh', { token: 'billing' })).toEqual({ error: { statusCode: 401, message: 'Refresh token reused' } });
    expect(await send('enroll', { token: 'billing' })).toEqual({
      error: { statusCode: 409, message: 'Authenticator already enrolled' },
    });
  });

  it('keeps concurrent messages apart while both are in flight', async () => {
    const [first, second] = await Promise.all([send('meet', { token: 'a' }), send('meet', { token: 'b' })]);
    expect([first, second]).toEqual([
      { reply: { before: 'svc-a', after: 'svc-a' } },
      { reply: { before: 'svc-b', after: 'svc-b' } },
    ]);
  });
});
