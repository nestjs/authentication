/**
 * `AuthenticationGuard` over HTTP without a server: the provider chain, challenges, pending
 * second factors, `@Authenticate({ providers, verifiedEmail })`, the per-request cache; what it
 * leaves on a fake socket per message, and per GraphQL operation on an upgrade request that
 * operations share; the route decorators; `WsAuthenticator` on fake sockets;
 * `AuthenticationContext` on its own.
 */
import { ForbiddenException, Logger, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants';
import { HttpAdapterHost, Reflector } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/internal';
import {
  Authenticate,
  AuthenticationContext,
  AuthenticationError,
  AuthenticationGuard,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentSession,
  CurrentUser,
  Public,
  WsAuthenticator,
  type AuthenticationResult,
} from '../lib/index.js';
import { AUTHENTICATION_METADATA } from '../lib/authentication.constants.js';
import { LOCK_REGISTRY } from '../lib/services/authentication-registry.service.js';

type User = { id: string; emailVerified?: boolean };
type Request = { headers: Record<string, string>; user?: unknown; session?: unknown };

/**
 * Answers what `x-<name>` says: `ok` a user, `pending` a pending sign-in, `bad` an AuthenticationError,
 * `expired` one with a code and details, `boom` an outage.
 */
class HeaderProvider extends AuthenticationProvider<User> {
  calls = 0;
  constructor(
    readonly name: string,
    private readonly challengeValue?: string,
  ) {
    super();
  }
  authenticate(context: ExecutionContext): AuthenticationResult<User> | null {
    this.calls++;
    switch (this.header(context, `x-${this.name}`)) {
      case 'ok':
        return { user: { id: this.name }, session: { via: this.name } };
      case 'verified':
        return { user: { id: this.name, emailVerified: true }, session: { via: this.name } };
      case 'pending':
        return { user: { id: this.name }, mfa: 'pending' };
      case 'no-user':
        return { user: null as never };
      case 'bad':
        throw new AuthenticationError(`bad ${this.name}`, { challenge: `${this.name} error="invalid"` });
      case 'expired':
        throw new AuthenticationError('Session expired', {
          code: 'invalid_session',
          details: { expiredAt: '2026-01-01T00:00:00.000Z' },
          challenge: `${this.name} error="invalid"`,
          cause: new Error('internal: row 42 has expires_at in the past'),
        });
      case 'boom':
        throw new Error('store down');
      default:
        return null;
    }
  }
  challenge() {
    return this.challengeValue;
  }
}
class First extends HeaderProvider {}
class Second extends HeaderProvider {}

function setup({ secondChallenge = 'Second realm="b"' }: { secondChallenge?: string | null } = {}) {
  const first = new First('first', 'First realm="a"');
  const second = new Second('second', secondChallenge ?? undefined);
  const registry = new AuthenticationRegistry();
  registry.registerProvider(second, { order: 2 });
  registry.registerProvider(first, { order: 1 });
  registry[LOCK_REGISTRY]({ log: false });

  const headers: Record<string, string>[] = [];
  const adapterHost = new HttpAdapterHost();
  adapterHost.httpAdapter = {
    setHeader: (response: Record<string, string>, name: string, value: string) => {
      response[name] = value;
      headers.push({ [name]: value });
    },
  } as never;

  const guard = new AuthenticationGuard(new Reflector(), adapterHost, registry);
  return { guard, first, second, headers };
}

class Routes {
  @Authenticate()
  required() {}

  @Authenticate({ optional: true })
  optional() {}

  @Authenticate({ providers: [Second] })
  secondOnly() {}

  @Authenticate({ verifiedEmail: true })
  verified() {}

  @Public()
  open() {}
}

function http(method: keyof Routes, headers: Record<string, string> = {}, request: Request = { headers }) {
  const response: Record<string, string> = {};
  const context = new ExecutionContextHost([request, response], Routes, Routes.prototype[method]);
  context.setType('http');
  return { context, request, response };
}

async function refusal(promise: Promise<unknown>) {
  return promise.then(
    () => {
      throw new Error('expected a refusal');
    },
    (error: unknown) => error as UnauthorizedException,
  );
}

describe('AuthenticationGuard over HTTP', () => {
  it('runs providers in `order`, stops at the first user, and mirrors it on request.user and request.session', async () => {
    const { guard, first, second } = setup();
    const { context, request } = http('required', { 'x-first': 'ok', 'x-second': 'ok' });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user).toEqual({ id: 'first' });
    expect(request.session).toEqual({ via: 'first' });
    expect([first.calls, second.calls]).toEqual([1, 0]);
  });

  it('leaves a `request.session` another package owns (express-session) alone, and still mirrors the user', async () => {
    const { guard } = setup();
    const owned = { cookie: {}, csrfSecret: 's', regenerate() {}, save() {} };
    const { context, request } = http('required', { 'x-first': 'ok' }, { headers: { 'x-first': 'ok' }, session: owned });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user).toEqual({ id: 'first' });
    expect(request.session).toBe(owned);

    // Anonymous on an optional route: still not nulled.
    const optional = http('optional', {}, { headers: {}, session: owned });
    await guard.canActivate(optional.context);
    expect(optional.request.session).toBe(owned);
  });

  it('counts a falsy user (0, an empty string, false) as none, and asks the next provider', async () => {
    const { second } = setup();
    const falsy = new (class extends HeaderProvider {
      authenticate(context: ExecutionContext) {
        this.calls++;
        const value = { zero: 0, empty: '', false: false }[this.header(context, 'x-falsy') as 'zero'];
        return { user: value as never };
      }
    })('falsy');
    const registry = new AuthenticationRegistry();
    registry.registerProvider(falsy, { order: 1 });
    registry.registerProvider(second, { order: 2 });
    registry[LOCK_REGISTRY]({ log: false });
    const chained = new AuthenticationGuard(new Reflector(), new HttpAdapterHost(), registry);

    for (const kind of ['zero', 'empty', 'false']) {
      const { context, request } = http('required', { 'x-falsy': kind, 'x-second': 'ok' });
      await expect(chained.canActivate(context)).resolves.toBe(true);
      expect(request.user).toEqual({ id: 'second' });
    }
  });

  it('with `providers: []`, refuses every caller, a cached result of another provider included', async () => {
    const { guard } = setup();
    class Closed {
      @Authenticate({ providers: [] })
      handle() {}
    }
    const request: Request = { headers: { 'x-first': 'ok' } };
    await guard.canActivate(http('required', {}, request).context); // caches `first`'s user on the request

    const context = new ExecutionContextHost([request, {}], Closed, Closed.prototype.handle);
    context.setType('http');
    await expect(refusal(guard.canActivate(context))).resolves.toBeInstanceOf(UnauthorizedException);
  });

  it('caches per GraphQL operation, not per `req`: over graphql-ws every operation of a socket shares one', async () => {
    const { guard, first } = setup();
    const upgrade: Request = { headers: { 'x-first': 'ok' } }; // the upgrade request, shared by the socket's operations
    const operation = () => {
      const context = new ExecutionContextHost([{}, {}, { req: upgrade }, {}], Routes, Routes.prototype.required);
      context.setType('graphql');
      return context;
    };

    await expect(guard.canActivate(operation())).resolves.toBe(true);
    upgrade.headers['x-first'] = 'bad'; // the session was revoked meanwhile
    await expect(refusal(guard.canActivate(operation()))).resolves.toMatchObject({ message: 'bad first' });
    expect(first.calls).toBe(2);

    // Root and field resolvers of one operation share its context: one run.
    const shared = operation();
    upgrade.headers['x-first'] = 'ok';
    await guard.canActivate(shared);
    await guard.canActivate(shared);
    expect(first.calls).toBe(3);
  });

  it('skips a result without a user', async () => {
    const { guard, second } = setup();
    const { context, request } = http('required', { 'x-first': 'no-user', 'x-second': 'ok' });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user).toEqual({ id: 'second' });
    expect(second.calls).toBe(1);
  });

  it('answers 401 with every provider’s challenge when nobody found credentials', async () => {
    const { guard, headers } = setup();
    const { context, response } = http('required');

    const error = await refusal(guard.canActivate(context));
    expect(error).toBeInstanceOf(UnauthorizedException);
    // `new UnauthorizedException()`'s body, key for key, plus the code: no `error`, which it never had.
    expect(JSON.stringify(error.getResponse())).toBe('{"message":"Unauthorized","statusCode":401,"code":"missing_credentials"}');
    expect(response).toEqual({ 'WWW-Authenticate': 'First realm="a", Second realm="b"' });
    expect(headers).toHaveLength(1);
  });

  it('leaves out providers without a challenge, and sends no header when none has one', async () => {
    const one = setup({ secondChallenge: null });
    const { context, response } = http('required');
    await refusal(one.guard.canActivate(context));
    expect(response).toEqual({ 'WWW-Authenticate': 'First realm="a"' });

    const { guard, headers } = setup({ secondChallenge: null });
    const restricted = http('secondOnly');
    await refusal(guard.canActivate(restricted.context));
    expect(headers).toEqual([]);
  });

  it('stops at a provider that refuses credentials, with its message and challenge, even on optional routes', async () => {
    const { guard, second } = setup();
    const { context, response } = http('optional', { 'x-first': 'bad', 'x-second': 'ok' });

    const error = await refusal(guard.canActivate(context));
    expect(error.getResponse()).toEqual({ message: 'bad first', error: 'Unauthorized', statusCode: 401 });
    expect(error.cause).toBeInstanceOf(AuthenticationError);
    expect(response).toEqual({ 'WWW-Authenticate': 'first error="invalid"' });
    expect(second.calls).toBe(0);
  });

  it('answers a provider’s refusal with its code and details, and nothing else of the error', async () => {
    const { guard } = setup();
    const { context, response } = http('required', { 'x-first': 'expired' });

    const error = await refusal(guard.canActivate(context));
    expect(JSON.stringify(error.getResponse())).toBe(
      '{"message":"Session expired","error":"invalid_session","statusCode":401,"code":"invalid_session","details":{"expiredAt":"2026-01-01T00:00:00.000Z"}}',
    );
    expect(error.cause).toMatchObject({ code: 'invalid_session' }); // the cause stays on the exception, for logs
    expect(response).toEqual({ 'WWW-Authenticate': 'first error="invalid"' });
  });

  it('lets any other error through untouched: an outage is a 500, not a 401', async () => {
    const { guard, second } = setup();
    const { context } = http('optional', { 'x-first': 'boom', 'x-second': 'ok' });

    await expect(guard.canActivate(context)).rejects.toThrow(new Error('store down'));
    expect(second.calls).toBe(0);
  });

  it('treats a pending sign-in as anonymous: 401 mfa_required where a user is required, null on optional routes', async () => {
    const { guard, second } = setup();

    const required = http('required', { 'x-first': 'pending', 'x-second': 'ok' });
    const error = await refusal(guard.canActivate(required.context));
    expect(error.getResponse()).toEqual({ message: 'Second factor required', error: 'mfa_required', code: 'mfa_required', statusCode: 401 });
    expect(required.response).toEqual({}); // no challenge: the credentials are fine
    expect(second.calls).toBe(0); // the pending result still ends the chain

    const optional = http('optional', { 'x-first': 'pending' });
    await expect(guard.canActivate(optional.context)).resolves.toBe(true);
    expect(optional.request.user).toBeNull();
    expect(optional.request.session).toBeNull();
  });

  it('passes anonymous callers of an optional route, recording null', async () => {
    const { guard } = setup();
    const { context, request } = http('optional');

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request).toMatchObject({ user: null, session: null });
  });

  it('never calls a provider, nor writes on the request, for @Public() routes', async () => {
    const { guard, first, second } = setup();
    const { context, request } = http('open', { 'x-first': 'bad' });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect([first.calls, second.calls]).toEqual([0, 0]);
    expect(request).not.toHaveProperty('user');
  });

  it('authenticates once per request, however many times the guard runs', async () => {
    const { guard, first } = setup();
    const request: Request = { headers: { 'x-first': 'ok' } };

    await guard.canActivate(http('required', {}, request).context);
    await guard.canActivate(http('optional', {}, request).context);
    expect(first.calls).toBe(1);
  });

  it('with `providers`, ignores what another provider found and runs only the named ones, without caching for other routes', async () => {
    const { guard, first, second } = setup();
    const request: Request = { headers: { 'x-first': 'ok', 'x-second': 'ok' } };

    await guard.canActivate(http('required', {}, request).context);
    expect(request.user).toEqual({ id: 'first' });

    await guard.canActivate(http('secondOnly', {}, request).context);
    expect(request.user).toEqual({ id: 'second' });
    expect([first.calls, second.calls]).toEqual([1, 1]);

    // The next route still sees the chain's answer, not the restricted one.
    await guard.canActivate(http('required', {}, request).context);
    expect(request.user).toEqual({ id: 'first' });
    expect(first.calls).toBe(1);

    // Only the named provider counts: the first provider's user does not pass.
    const onlyFirst = http('secondOnly', { 'x-first': 'ok' });
    await refusal(guard.canActivate(onlyFirst.context));
    expect(onlyFirst.response).toEqual({ 'WWW-Authenticate': 'Second realm="b"' });
  });

  it('`verifiedEmail` without a handler reads `user.emailVerified`, and refuses others with a 403', async () => {
    const { guard } = setup();

    const unverified = http('verified', { 'x-first': 'ok' });
    const error = await refusal(guard.canActivate(unverified.context));
    expect(error).toBeInstanceOf(ForbiddenException);
    expect(error.getResponse()).toEqual({ message: 'Email address not verified', error: 'email_unverified', code: 'email_unverified', statusCode: 403 });
    expect(unverified.request).not.toHaveProperty('user');
    expect(unverified.response).toEqual({}); // a 403 carries no challenge

    await expect(guard.canActivate(http('verified', { 'x-first': 'verified' }).context)).resolves.toBe(true);
  });
});

describe('AuthenticationGuard over ws', () => {
  const USER_OF = Symbol.for('nestjs.authentication.userOf');
  type Socket = { request: Request; user?: unknown; [USER_OF]?: (context: ExecutionContext) => unknown };

  /** One message on `client`, handled by `method`. */
  function message(client: Socket, method: keyof Routes, data: unknown = {}) {
    const context = new ExecutionContextHost([client, data], Routes, Routes.prototype[method]);
    context.setType('ws');
    return context;
  }

  it("leaves on the socket, for other packages, each message's own user: null for a @Public() one", async () => {
    const { guard } = setup();
    const client: Socket = { request: { headers: { 'x-first': 'ok' } } };
    const signedIn = message(client, 'required');
    const open = message(client, 'open', 'hi');

    await guard.canActivate(signedIn);
    await guard.canActivate(open);

    // The socket's own copy is the last authenticated message's: a @Public() one leaves it alone.
    expect(client.user).toEqual({ id: 'first' });
    expect(client[USER_OF]!(open)).toBeNull();
    expect(client[USER_OF]!(signedIn)).toEqual({ id: 'first' });
  });

  it('answers for a message the guard did not see with what its connection recorded, undefined before anything was', async () => {
    const { guard } = setup();
    const client: Socket = { request: { headers: { 'x-first': 'ok' } } };

    await guard.canActivate(message(client, 'open'));
    expect(client[USER_OF]!(message(client, 'required'))).toBeUndefined();

    await guard.canActivate(message(client, 'required'));
    expect(client[USER_OF]!(message(client, 'required'))).toEqual({ id: 'first' });
  });
});

describe('AuthenticationGuard over graphql-ws', () => {
  const USER_OF = Symbol.for('nestjs.authentication.userOf');
  type Upgrade = Request & { [USER_OF]?: (context: ExecutionContext) => unknown };

  /** An operation on a socket: its own context, around the upgrade request every operation of the socket shares. */
  function operation(req: Upgrade) {
    const gqlContext = { req };
    return (method: keyof Routes) => {
      const context = new ExecutionContextHost([{}, {}, gqlContext, {}], Routes, Routes.prototype[method]);
      context.setType('graphql');
      return context;
    };
  }

  it("leaves on `req`, for other packages, each operation's own user: null for one that recorded nothing (@Public())", async () => {
    const { guard } = setup();
    const upgrade: Upgrade = { headers: { 'x-first': 'ok' } };
    const signedIn = operation(upgrade)('required');
    const open = operation(upgrade)('open');

    await guard.canActivate(signedIn);
    await guard.canActivate(open);

    // The request's own copy is the last authenticated operation's, as a ws client's is.
    expect(upgrade.user).toEqual({ id: 'first' });
    expect(upgrade[USER_OF]!(open)).toBeNull();
    expect(upgrade[USER_OF]!(signedIn)).toEqual({ id: 'first' });
    // Not `undefined`, which would send a caller back to `req.user`: the request is not the operation's own.
    expect(upgrade[USER_OF]!(operation(upgrade)('required'))).toBeNull();
  });

  it("shares one operation's result between its resolvers, a @Public() root field included, as over HTTP", async () => {
    const { guard } = setup();
    const upgrade: Upgrade = { headers: { 'x-first': 'ok' } };
    const resolver = operation(upgrade);

    await guard.canActivate(resolver('required'));
    expect(upgrade[USER_OF]!(resolver('open'))).toEqual({ id: 'first' });
  });

  it('leaves no such function on an HTTP request, which is per call', async () => {
    const { guard } = setup();
    const { context, request } = http('required', { 'x-first': 'ok' });

    await guard.canActivate(context);
    expect(request.user).toEqual({ id: 'first' });
    expect(USER_OF in request).toBe(false);
  });
});

describe('route decorators', () => {
  const metadata = (target: object) => Reflect.getMetadata(AUTHENTICATION_METADATA, target);

  it('stack: later decorators merge over earlier ones, and fields left undefined keep what was there', () => {
    class Stacked {
      @Authenticate({ mfa: true })
      @Authenticate({ optional: true, providers: undefined })
      both() {}

      @Authenticate({ optional: undefined })
      @Authenticate({ optional: true })
      kept() {}

      @Authenticate()
      @Public()
      reopened() {}
    }

    expect(metadata(Stacked.prototype.both)).toEqual({ optional: true, mfa: true, public: false });
    expect(metadata(Stacked.prototype.kept)).toEqual({ optional: true, public: false });
    expect(metadata(Stacked.prototype.reopened)).toEqual({ public: false });
  });

  it('store class options on the class and method options on the method', () => {
    @Public()
    class Open {
      @Authenticate({ verifiedEmail: true })
      strict() {}
      plain() {}
    }

    expect(metadata(Open)).toEqual({ public: true });
    expect(metadata(Open.prototype.strict)).toEqual({ verifiedEmail: true, public: false });
    expect(metadata(Open.prototype.plain)).toBeUndefined();
  });

  function factoryOf(decorator: ParameterDecorator) {
    class Target {
      handle(_value: unknown) {}
    }
    decorator(Target.prototype, 'handle', 0);
    const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, Target, 'handle');
    const { factory, data } = Object.values(args)[0] as { factory: (data: unknown, ctx: ExecutionContext) => unknown; data: unknown };
    return (context: ExecutionContext) => factory(data, context);
  }

  it('@CurrentUser() and @CurrentSession() give null before authentication and for anonymous callers', async () => {
    const { guard } = setup();
    const user = factoryOf(CurrentUser());
    const email = factoryOf(CurrentUser('email' as never));
    const session = factoryOf(CurrentSession());

    const fresh = http('optional');
    expect([user(fresh.context), email(fresh.context), session(fresh.context)]).toEqual([null, null, null]);

    await guard.canActivate(fresh.context);
    expect([user(fresh.context), email(fresh.context), session(fresh.context)]).toEqual([null, null, null]);

    const signedIn = http('required', { 'x-first': 'ok' });
    await guard.canActivate(signedIn.context);
    expect([user(signedIn.context), factoryOf(CurrentUser('id' as never))(signedIn.context), session(signedIn.context)]).toEqual([
      { id: 'first' },
      'first',
      { via: 'first' },
    ]);
  });

  it("@CurrentUser() and @CurrentSession() give a GraphQL operation its own result, not another's on a shared `req`", async () => {
    const { guard } = setup();
    const user = factoryOf(CurrentUser());
    const session = factoryOf(CurrentSession());
    const upgrade: Request = { headers: { 'x-first': 'ok' } };
    const operation = (method: keyof Routes, gqlContext = { req: upgrade }) => {
      const context = new ExecutionContextHost([{}, {}, gqlContext, {}], Routes, Routes.prototype[method]);
      context.setType('graphql');
      return context;
    };

    const signedIn = { req: upgrade };
    await guard.canActivate(operation('required', signedIn));
    const sameOperation = operation('required', signedIn);
    expect([user(sameOperation), session(sameOperation)]).toEqual([{ id: 'first' }, { via: 'first' }]);

    const open = operation('open');
    await guard.canActivate(open);
    expect(upgrade.user).toEqual({ id: 'first' }); // the socket's last user...
    expect([user(open), session(open)]).toEqual([null, null]); // ...is not this operation's
  });
});

describe('WsAuthenticator', () => {
  class Client {
    closed?: [number, string];
    user?: unknown;
    request?: unknown;
    constructor(readonly handshake?: { headers: Record<string, string> }) {}
    close(code: number, reason: string) {
      this.closed = [code, reason];
    }
  }

  function authenticatorWith(provider: AuthenticationProvider<User>) {
    const registry = new AuthenticationRegistry();
    registry.registerProvider(provider);
    registry[LOCK_REGISTRY]({ log: false });
    return new WsAuthenticator(registry);
  }

  it('keeps the upgrade request on a `ws` client, where providers read its headers, and records the user', async () => {
    const auth = authenticatorWith(new First('first'));
    const client = new Client();
    const upgrade = { headers: { 'x-first': 'ok' } };

    await expect(auth.authenticateConnection(client, upgrade as never)).resolves.toMatchObject({ user: { id: 'first' } });
    expect(client.request).toBe(upgrade);
    expect(client.user).toEqual({ id: 'first' });
    expect(client.closed).toBeUndefined();
  });

  it('reads socket.io’s handshake, and leaves client.request alone there', async () => {
    const auth = authenticatorWith(new First('first'));
    const client = new Client({ headers: { 'x-first': 'ok' } });

    await expect(auth.authenticateConnection(client, { headers: {} } as never)).resolves.toMatchObject({ user: { id: 'first' } });
    expect(client.request).toBeUndefined();
  });

  it('closes an anonymous connection with 1008, or keeps it with `required: false`', async () => {
    const auth = authenticatorWith(new First('first'));

    const strict = new Client({ headers: {} });
    await expect(auth.authenticateConnection(strict)).resolves.toBeNull();
    expect(strict.closed).toEqual([1008, 'Unauthorized']);
    expect(strict.user).toBeNull();

    const lenient = new Client({ headers: {} });
    await expect(auth.authenticateConnection(lenient, undefined, { required: false })).resolves.toBeNull();
    expect(lenient.closed).toBeUndefined();
  });

  it('counts refused credentials and pending sign-ins as anonymous, not as failures', async () => {
    const auth = authenticatorWith(new First('first'));
    const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});

    for (const value of ['bad', 'pending']) {
      const client = new Client({ headers: { 'x-first': value } });
      await expect(auth.authenticateConnection(client)).resolves.toBeNull();
      expect(client.closed).toEqual([1008, 'Unauthorized']);
      expect(client.user).toBeNull();
    }
    expect(logged).not.toHaveBeenCalled();
    logged.mockRestore();
  });

  it('disconnects a socket.io client, which has no close(), on failures', async () => {
    const auth = authenticatorWith(new First('first'));
    const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
    const disconnect = vi.fn();

    await expect(auth.authenticateConnection({ handshake: { headers: {} }, disconnect })).resolves.toBeNull();
    await expect(auth.authenticateConnection({ handshake: { headers: { 'x-first': 'boom' } }, disconnect })).resolves.toBeNull();

    expect(disconnect.mock.calls).toEqual([[true], [true]]);
    expect(logged).toHaveBeenCalledWith('Authenticating a WebSocket connection failed', expect.stringContaining('store down'));
    logged.mockRestore();
  });
});

describe('AuthenticationContext', () => {
  it('reads the user and session of the scope it runs in, and nothing outside', async () => {
    const auth = new AuthenticationContext<User, { via: string }>();
    expect([auth.user, auth.session, auth.isAuthenticated]).toEqual([null, null, false]);

    const inside = auth.run({ user: { id: 'u1' }, session: { via: 'job' } }, () => [auth.user, auth.session, auth.isAuthenticated]);
    expect(inside).toEqual([{ id: 'u1' }, { via: 'job' }, true]);

    const anonymous = auth.run(null, () => [auth.user, auth.session, auth.isAuthenticated]);
    expect(anonymous).toEqual([null, null, false]);
  });

  it('restores the outer scope after a nested run(), across awaits', async () => {
    const auth = new AuthenticationContext<User>();
    const seen = await auth.run({ user: { id: 'outer' } }, async () => {
      const inner = await auth.run({ user: { id: 'inner' } }, async () => {
        await Promise.resolve();
        return auth.user?.id;
      });
      return [inner, auth.user?.id];
    });
    expect(seen).toEqual(['inner', 'outer']);
  });

  it('requireUser() throws a plain AuthenticationError in a nested anonymous scope too', () => {
    const auth = new AuthenticationContext<User>();
    const error = auth.run({ user: { id: 'u1' } }, () =>
      auth.run(null, () => {
        try {
          auth.requireUser();
        } catch (caught) {
          return caught;
        }
        return undefined;
      }),
    );
    expect(error).toBeInstanceOf(AuthenticationError);
    expect(error).toMatchObject({ status: 401, message: 'Unauthorized' });
  });

  it('shares its scope with every instance built on the same AuthenticationScope only', () => {
    const one = new AuthenticationContext<User>();
    const other = new AuthenticationContext<User>();
    expect(one.run({ user: { id: 'u1' } }, () => other.user)).toBeNull();
  });
});
