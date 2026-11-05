import { AsyncLocalStorage } from 'node:async_hooks';
import type { IncomingHttpHeaders } from 'node:http';
import { Injectable, type ExecutionContext } from '@nestjs/common';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';

export interface Scope {
  result: AuthenticationResult<any, any> | null;
  /** The call being handled; absent inside `AuthenticationContext.run()`. */
  context?: ExecutionContext;
}

/** The request and response of an HTTP call, as the platform (Express, Fastify) provides them. */
export interface HttpExchange {
  request: { headers: IncomingHttpHeaders; method?: string; ip?: string };
  response?: unknown;
}

/**
 * The call the interceptor is handling, for the param decorators, which have no instance to ask:
 * one store for the process, entered with the instance's own by `AuthenticationScopeInterceptor`.
 */
const calls = new AsyncLocalStorage<Scope>();

/** @internal Runs `fn` as the handling of this call (the interceptor, around `next.handle()`). */
export function runCall<R>(scope: Scope, fn: () => R): R {
  return calls.run(scope, fn);
}

/**
 * @internal What the handler of this call sees: the result the guard recorded for it, when the
 * interceptor is handling this handler (param decorators are resolved inside it).
 */
export function scopedResult(context: ExecutionContext): Scope['result'] | undefined {
  const call = calls.getStore();
  return call?.context && call.context.getHandler() === context.getHandler() ? call.result : undefined;
}

/**
 * @internal The per-call scope behind `AuthenticationContext` and
 * `SignInService`: its own `AsyncLocalStorage`, opened around each handler
 * by `AuthenticationScopeInterceptor`.
 */
@Injectable()
export class AuthenticationScope {
  private readonly storage = new AsyncLocalStorage<Scope>();

  get current(): Scope | undefined {
    return this.storage.getStore();
  }

  run<R>(scope: Scope, fn: () => R): R {
    return this.storage.run(scope, fn);
  }

  /**
   * The HTTP request and response of the current call: an HTTP handler, a
   * GraphQL resolver whose context carries `req` (and `res`), or an
   * `@nestjs/mcp` call that arrived over HTTP (its context, the second of
   * its arguments, carries `request`). An MCP call has no response of its own
   * to set cookies on: the MCP SDK writes the HTTP response. An `@nestjs/ai`
   * agent function called in an HTTP request carries it the same way, and has
   * no response either: the route that runs the agent owns it.
   */
  exchange(): HttpExchange | undefined {
    const context = this.current?.context;

    switch (context?.getType<string>()) {
      case 'http': {
        const http = context!.switchToHttp();
        return { request: http.getRequest(), response: http.getResponse() };
      }
      case 'graphql': {
        const gql = context!.getArgByIndex(2);
        return gql?.req ? { request: gql.req, response: gql.res } : undefined;
      }
      case 'mcp':
      case 'ai': {
        const request = context!.getArgByIndex(1)?.request;
        return request?.headers ? { request } : undefined;
      }
      default:
        return undefined;
    }
  }
}
