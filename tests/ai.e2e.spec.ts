/**
 * Calls of agent functions (`@nestjs/ai`), on Express and Fastify: the global guard on each call, `@CurrentUser()`
 * and `AuthenticationContext` in them, one authentication per request when the route that runs the agent is guarded
 * too, the refusals, and jobs, where there is no request. `@nestjs/ai` is not a dependency: a stand-in calls functions
 * the way it does, through Nest's `ExternalContextCreator` with the context type `ai` and the arguments
 * `[input, context]`, `context.request` being the HTTP request the agent runs in (none in a job).
 */
import {
  Body,
  Controller,
  HttpCode,
  HttpException,
  Injectable,
  Module,
  Post,
  Req,
  type ExecutionContext,
  type INestApplication,
  type OnModuleInit,
} from '@nestjs/common';
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants.js';
import { ExternalContextCreator } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  Authenticate,
  AuthenticationContext,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentUser,
  Public,
} from '../lib/index.js';
import { ApiKeyRepository, ApiKeysModule, AuthProvidersModule, authenticationModule, UsersModule, type User } from './fixtures.js';

/** The second argument of a call: `@nestjs/ai`'s `AgentFunctionContext`, as far as this package reads it. */
interface AgentCall {
  name: string;
  request?: { headers: Record<string, unknown>; user?: unknown };
  user?: unknown;
}

type FunctionResult = { output: unknown } | { error: string; status: number; errorCode?: string };

/** Calls functions as `@nestjs/ai` does, and answers an `HttpException` with the error the model reads. */
@Injectable()
class AgentStandIn {
  private readonly functions = new Map<string, (input: unknown, call: AgentCall) => Promise<unknown>>();

  constructor(private readonly contexts: ExternalContextCreator) {}

  register(instance: object, methodName: string) {
    const method = Object.getPrototypeOf(instance)[methodName];
    const paramsFactory = { exchangeKeyForValue: () => undefined };
    this.functions.set(
      methodName,
      this.contexts.create(instance, method, methodName, ROUTE_ARGS_METADATA, paramsFactory, undefined, undefined, undefined, 'ai'),
    );
  }

  async call(name: string, input: unknown, call: AgentCall): Promise<FunctionResult> {
    try {
      return { output: await this.functions.get(name)!(input, call) };
    } catch (error) {
      if (!(error instanceof HttpException)) {
        throw error;
      }
      const body = error.getResponse() as { message?: string; errorCode?: string };
      return { error: body.message ?? error.message, status: error.getStatus(), errorCode: body.errorCode };
    }
  }
}

@Injectable()
class SupportFunctions implements OnModuleInit {
  constructor(
    private readonly auth: AuthenticationContext<User>,
    private readonly agent: AgentStandIn,
  ) {}

  onModuleInit() {
    for (const name of ['whoami', 'mirrored', 'hello', 'feed']) {
      this.agent.register(this, name);
    }
  }

  whoami(@CurrentUser() user: User) {
    return { id: user.id, fromContext: this.auth.user?.id };
  }

  /** What Passport-era code reads: `request.user`. */
  mirrored(_input: unknown, call: AgentCall) {
    return (call.request?.user as User | undefined)?.id;
  }

  @Public()
  hello() {
    return `hello ${this.auth.user?.id ?? 'guest'}`;
  }

  @Authenticate({ optional: true })
  feed(@CurrentUser() user: User | null) {
    return user?.id ?? null;
  }
}

/** A route that runs the agent, `@Public()`: each function call is authenticated on its own. */
@Controller('assistant')
@Public()
class AssistantController {
  constructor(private readonly agent: AgentStandIn) {}

  @Post()
  @HttpCode(200)
  call(@Req() req: AgentCall['request'], @Body() body: { name: string; input?: object }) {
    return this.agent.call(body.name, body.input ?? {}, { name: body.name, request: req });
  }
}

/** The same route without `@Public()`: its own guard authenticates the request first. */
@Controller('guarded-assistant')
class GuardedAssistantController extends AssistantController {}

@Module({
  imports: [authenticationModule(), UsersModule, AuthProvidersModule, ApiKeysModule],
  controllers: [AssistantController, GuardedAssistantController],
  providers: [AgentStandIn, SupportFunctions],
})
class AgentAppModule {}

describe.each(adapters.map((adapter) => adapter.name))('agent function calls in an HTTP request (%s)', (adapter) => {
  let app: INestApplication;
  const callFunction = (name: string, { key, path = '/assistant' }: { key?: string; path?: string } = {}) => {
    const req = request(app.getHttpServer()).post(path);
    if (key) {
      req.set('x-api-key', key);
    }
    return req.send({ name, input: {} }).expect(200);
  };

  beforeAll(async () => {
    app = await createApp(adapter, AgentAppModule);
  });
  afterAll(() => app.close());

  it('authenticates the call from the request the agent runs in: the global guard, @CurrentUser(), AuthenticationContext', async () => {
    const res = await callFunction('whoami', { key: 'key-ci' });
    expect(res.body).toEqual({ output: { id: 'svc-ci', fromContext: 'svc-ci' } });
    expect((await callFunction('mirrored', { key: 'key-ci' })).body).toEqual({ output: 'svc-ci' });
  });

  it('refuses a call without credentials with an UnauthorizedException, which @nestjs/ai gives the model', async () => {
    const res = await callFunction('whoami');
    expect(res.body).toEqual({ error: 'Unauthorized', status: 401, errorCode: 'missing_credentials' });
  });

  it('refuses unknown credentials the same way, the provider having refused them', async () => {
    const res = await callFunction('whoami', { key: 'key-unknown' });
    expect(res.body).toMatchObject({ error: 'unknown API key', status: 401 });
  });

  it('leaves @Public() calls open, and lets @Authenticate({ optional: true }) ones through anonymous', async () => {
    expect((await callFunction('hello')).body).toEqual({ output: 'hello guest' });
    expect((await callFunction('feed')).body).toEqual({ output: null });
    expect((await callFunction('feed', { key: 'key-ci' })).body).toEqual({ output: 'svc-ci' });
  });

  it('authenticates once when the route that runs the agent is guarded too', async () => {
    const lookups = vi.spyOn(app.get(ApiKeyRepository), 'find');
    expect((await callFunction('whoami', { key: 'key-ci', path: '/guarded-assistant' })).body).toEqual({
      output: { id: 'svc-ci', fromContext: 'svc-ci' },
    });
    expect(lookups).toHaveBeenCalledTimes(1);
    lookups.mockRestore();
  });

  it('keeps concurrent calls apart', async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => callFunction('whoami', { ...(i % 2 ? { key: 'key-ci' } : {}) })),
    );
    results.forEach((res, i) => {
      expect(res.body).toEqual(i % 2 ? { output: { id: 'svc-ci', fromContext: 'svc-ci' } } : expect.objectContaining({ status: 401 }));
    });
  });
});

/**
 * A job's code gives the agent the user it acts for, on the call's context. The app's providers read credentials
 * from a request, and there is none, so the call is anonymous to them; a provider of the app's own can trust that
 * user.
 */
@Injectable()
class JobUserAuth extends AuthenticationProvider<User> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this, { order: 3 });
  }

  authenticate(context: ExecutionContext) {
    const call = context.getArgByIndex(1) as AgentCall | undefined;
    if (context.getType<string>() !== 'ai' || call?.request || !call?.user) {
      return null;
    }
    return { user: call.user as User };
  }
}

describe('agent function calls in a job', () => {
  const job = (name: string, user?: User): AgentCall => ({ name, ...(user && { user }) });
  const nightly = { id: 'job-nightly', email: 'jobs@example.com', name: 'Nightly', roles: [] } as unknown as User;

  it("treats a call as anonymous, refused where a user is required, and leaves the job's user on the context", async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AgentAppModule] }).compile();
    await moduleRef.init();
    try {
      const agent = moduleRef.get(AgentStandIn);
      expect(await agent.call('whoami', {}, job('whoami', nightly))).toMatchObject({ status: 401 });
      const call = job('hello', nightly);
      expect(await agent.call('hello', {}, call)).toEqual({ output: 'hello guest' });
      // What @nestjs/authorization's @Can() reads in a job.
      expect(call.user).toBe(nightly);
    } finally {
      await moduleRef.close();
    }
  });

  it("authenticates with a provider of the app's own that trusts the job's user", async () => {
    @Module({ imports: [UsersModule], providers: [JobUserAuth] })
    class JobUserModule {}
    @Module({
      imports: [authenticationModule(), UsersModule, AuthProvidersModule, ApiKeysModule, JobUserModule],
      providers: [AgentStandIn, SupportFunctions],
    })
    class JobAppModule {}

    const moduleRef = await Test.createTestingModule({ imports: [JobAppModule] }).compile();
    await moduleRef.init();
    try {
      const agent = moduleRef.get(AgentStandIn);
      expect(await agent.call('whoami', {}, job('whoami', nightly))).toEqual({
        output: { id: 'job-nightly', fromContext: 'job-nightly' },
      });
      expect(await agent.call('feed', {}, job('feed', nightly))).toEqual({ output: 'job-nightly' });
      expect(await agent.call('whoami', {}, job('whoami'))).toMatchObject({ status: 401 });
    } finally {
      await moduleRef.close();
    }
  });
});
