/**
 * Calls of an MCP server's tools (`@nestjs/mcp`), on Express and Fastify: the global guard on each call,
 * `@CurrentUser()` and `AuthenticationContext` in them, one authentication per request when the endpoint's route is
 * guarded too, the refusals, and stdio, where there is no request. `@nestjs/mcp` is not a dependency: a stand-in
 * endpoint calls tools the way it does, through Nest's `ExternalContextCreator` with the context type `mcp` and the
 * arguments `[input, context]`, `context.request` being the HTTP request the call arrived in (none over stdio).
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

/** The second argument of a call: `@nestjs/mcp`'s `McpContext`, as far as this package reads it. */
interface McpCall {
  kind: 'tool';
  name: string;
  transport: 'http' | 'stdio';
  request?: { headers: Record<string, unknown>; user?: unknown };
}

type ToolResult = { result: unknown } | { isError: true; status: number; message: string; errorCode?: string };

/** Calls tools as `@nestjs/mcp` does, and answers an `HttpException` with a tool error carrying its message. */
@Injectable()
class McpStandIn {
  private readonly tools = new Map<string, (input: unknown, call: McpCall) => Promise<unknown>>();

  constructor(private readonly contexts: ExternalContextCreator) {}

  register(instance: object, methodName: string) {
    const method = Object.getPrototypeOf(instance)[methodName];
    const paramsFactory = { exchangeKeyForValue: () => undefined };
    this.tools.set(
      methodName,
      this.contexts.create(instance, method, methodName, ROUTE_ARGS_METADATA, paramsFactory, undefined, undefined, undefined, 'mcp'),
    );
  }

  async call(name: string, input: unknown, call: McpCall): Promise<ToolResult> {
    try {
      return { result: await this.tools.get(name)!(input, call) };
    } catch (error) {
      if (!(error instanceof HttpException)) {
        throw error;
      }
      const body = error.getResponse() as { message?: string; errorCode?: string };
      return { isError: true, status: error.getStatus(), message: body.message ?? error.message, errorCode: body.errorCode };
    }
  }
}

@Injectable()
class SupportTools implements OnModuleInit {
  constructor(
    private readonly auth: AuthenticationContext<User>,
    private readonly mcp: McpStandIn,
  ) {}

  onModuleInit() {
    for (const name of ['whoami', 'mirrored', 'hello', 'feed']) {
      this.mcp.register(this, name);
    }
  }

  whoami(@CurrentUser() user: User) {
    return { id: user.id, fromContext: this.auth.user?.id };
  }

  /** What Passport-era code reads: `request.user`. */
  mirrored(_input: unknown, call: McpCall) {
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

/** The MCP endpoint, as `@nestjs/mcp` adds it: a route, here `@Public()` (as with its own OAuth `auth` option). */
@Controller('mcp')
@Public()
class McpController {
  constructor(private readonly mcp: McpStandIn) {}

  @Post()
  @HttpCode(200)
  call(@Req() req: McpCall['request'], @Body() body: { name: string; arguments?: object }) {
    return this.mcp.call(body.name, body.arguments ?? {}, { kind: 'tool', name: body.name, transport: 'http', request: req });
  }
}

/** The same endpoint without `@Public()`: the route's own guard authenticates the request first. */
@Controller('guarded-mcp')
class GuardedMcpController extends McpController {}

@Module({
  imports: [authenticationModule(), UsersModule, AuthProvidersModule, ApiKeysModule],
  controllers: [McpController, GuardedMcpController],
  providers: [McpStandIn, SupportTools],
})
class McpAppModule {}

describe.each(adapters.map((adapter) => adapter.name))('MCP tool calls over HTTP (%s)', (adapter) => {
  let app: INestApplication;
  const callTool = (name: string, { key, path = '/mcp' }: { key?: string; path?: string } = {}) => {
    const req = request(app.getHttpServer()).post(path);
    if (key) {
      req.set('x-api-key', key);
    }
    return req.send({ name, arguments: {} }).expect(200);
  };

  beforeAll(async () => {
    app = await createApp(adapter, McpAppModule);
  });
  afterAll(() => app.close());

  it('authenticates the call from the request it arrived in: the global guard, @CurrentUser(), AuthenticationContext', async () => {
    const res = await callTool('whoami', { key: 'key-ci' });
    expect(res.body).toEqual({ result: { id: 'svc-ci', fromContext: 'svc-ci' } });
    expect((await callTool('mirrored', { key: 'key-ci' })).body).toEqual({ result: 'svc-ci' });
  });

  it('refuses a call without credentials with an UnauthorizedException, which @nestjs/mcp answers with a tool error', async () => {
    const res = await callTool('whoami');
    expect(res.body).toEqual({ isError: true, status: 401, message: 'Unauthorized', errorCode: 'missing_credentials' });
  });

  it('refuses unknown credentials the same way, the provider having refused them', async () => {
    const res = await callTool('whoami', { key: 'key-unknown' });
    expect(res.body).toMatchObject({ isError: true, status: 401, message: 'unknown API key' });
  });

  it('leaves @Public() calls open, and lets @Authenticate({ optional: true }) ones through anonymous', async () => {
    expect((await callTool('hello')).body).toEqual({ result: 'hello guest' });
    expect((await callTool('feed')).body).toEqual({ result: null });
    expect((await callTool('feed', { key: 'key-ci' })).body).toEqual({ result: 'svc-ci' });
  });

  it('authenticates once when the route the calls arrive on is guarded too', async () => {
    const lookups = vi.spyOn(app.get(ApiKeyRepository), 'find');
    expect((await callTool('whoami', { key: 'key-ci', path: '/guarded-mcp' })).body).toEqual({
      result: { id: 'svc-ci', fromContext: 'svc-ci' },
    });
    expect(lookups).toHaveBeenCalledTimes(1);
    lookups.mockRestore();
  });

  it('keeps concurrent calls apart', async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => callTool('whoami', { ...(i % 2 ? { key: 'key-ci' } : {}) })),
    );
    results.forEach((res, i) => {
      expect(res.body).toEqual(i % 2 ? { result: { id: 'svc-ci', fromContext: 'svc-ci' } } : expect.objectContaining({ status: 401 }));
    });
  });
});

/**
 * Over stdio, the client launched the server: the MCP spec takes credentials from the environment, and there is no
 * request to read them from. The app's providers find nothing, so calls are anonymous; a provider of the app's own
 * can authenticate them.
 */
@Injectable()
class LocalUserAuth extends AuthenticationProvider<User> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this, { order: 3 });
  }

  authenticate(context: ExecutionContext) {
    const call = context.getArgByIndex(1) as McpCall | undefined;
    if (context.getType<string>() !== 'mcp' || call?.request || !process.env.MCP_LOCAL_USER) {
      return null;
    }
    return { user: { id: process.env.MCP_LOCAL_USER, email: 'local@example.com', name: 'Local', roles: [] } };
  }
}

describe('MCP tool calls over stdio', () => {
  const stdio = (name: string): McpCall => ({ kind: 'tool', name, transport: 'stdio' });

  it('treats a call as anonymous: refused where a user is required, open where none is', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [McpAppModule] }).compile();
    await moduleRef.init();
    const mcp = moduleRef.get(McpStandIn);
    expect(await mcp.call('whoami', {}, stdio('whoami'))).toMatchObject({ isError: true, status: 401 });
    expect(await mcp.call('hello', {}, stdio('hello'))).toEqual({ result: 'hello guest' });
    await moduleRef.close();
  });

  it('authenticates with a provider that reads the environment, and records the user on the call', async () => {
    @Module({ imports: [UsersModule], providers: [LocalUserAuth] })
    class LocalUserModule {}
    @Module({
      imports: [authenticationModule(), UsersModule, AuthProvidersModule, ApiKeysModule, LocalUserModule],
      providers: [McpStandIn, SupportTools],
    })
    class StdioAppModule {}

    vi.stubEnv('MCP_LOCAL_USER', 'local-dev');
    const moduleRef = await Test.createTestingModule({ imports: [StdioAppModule] }).compile();
    await moduleRef.init();
    try {
      const mcp = moduleRef.get(McpStandIn);
      expect(await mcp.call('whoami', {}, stdio('whoami'))).toEqual({ result: { id: 'local-dev', fromContext: 'local-dev' } });
      const call = stdio('feed');
      expect(await mcp.call('feed', {}, call)).toEqual({ result: 'local-dev' });
      // No request to mirror it on: the call's own context carries it.
      expect((call as McpCall & { user?: User }).user?.id).toBe('local-dev');
    } finally {
      vi.unstubAllEnvs();
      await moduleRef.close();
    }
  });
});
