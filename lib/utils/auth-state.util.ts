import type { ExecutionContext } from '@nestjs/common';
import { scopedResult } from '../context/authentication-scope.service.js';
import { graphqlContextOf } from './graphql-context.util.js';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';

const AUTH_STATE = Symbol.for('nestjs.authentication.state');
/** The `session` this package last mirrored on a carrier, to tell it from another package's. */
const MIRRORED_SESSION = Symbol.for('nestjs.authentication.mirrored-session');
/**
 * Where a ws client, or GraphQL's `context.req`, carries {@link userOf}, for other packages to call
 * without importing this one (`@nestjs/authorization` does). A registry symbol, so every copy of
 * either package agrees.
 */
const USER_OF = Symbol.for('nestjs.authentication.userOf');

type Headers = Record<string, string | string[] | undefined>;
type State = AuthenticationResult<any, any> | null;

/**
 * Per-call state. For HTTP and RPC the carrier below is already per call, and
 * a GraphQL operation keeps its own on its context ({@link stateCarrierOf}). A
 * WebSocket carrier is the socket, which outlives the message and is shared
 * by concurrent messages, so ws calls are also keyed by their message payload
 * (the same object reaches guards, interceptors and param decorators) or, for
 * primitive payloads, by the args array (shared by guards and interceptors).
 */
const perCall = new WeakMap<object, State>();

function callKeys(context: ExecutionContext): object[] {
  if (context.getType() !== 'ws') {
    return [];
  }

  const data = context.switchToWs().getData();
  const keys: object[] = [context.getArgs()];
  if (typeof data === 'object' && data !== null) {
    keys.push(data);
  }
  return keys;
}

/**
 * The context of an `@nestjs/mcp` call (a tool, resource or prompt) or of an
 * `@nestjs/ai` agent function call, read from its arguments, `[input,
 * context]`, so this package needs neither dependency. Its `request` is the
 * HTTP platform's request: the one an MCP call arrived in (a plain
 * `{ method, url, headers }` object for `@nestjs/mcp/testing`'s in-memory
 * client), or the one the agent runs in. Absent over stdio, and in a job.
 */
function callContextOf(context: ExecutionContext): { request?: Record<PropertyKey, any> } | undefined {
  const call = context.getArgByIndex(1);
  return typeof call === 'object' && call !== null ? call : undefined;
}

/**
 * The object that carries the result for one call, mirrored as `user` /
 * `session` where Passport-era code and `@nestjs/authorization` look:
 * the request (http), the client socket (ws), the transport context (rpc),
 * `context.req` (graphql; over graphql-ws, the socket's upgrade request, which
 * every operation of the socket shares), and for an MCP call (`mcp`) the HTTP
 * request it arrived in, else (over stdio) its own context object. Each MCP
 * request travels in an HTTP request of its own, so the request is per call,
 * and it is the one the endpoint's route was authenticated on: a guard there
 * and on the call authenticate once. An agent function call (`ai`) is carried
 * the same way: the HTTP request the agent runs in, which the route that runs
 * it authenticated, else (in a job) its own context object.
 */
function carrierOf(context: ExecutionContext): Record<PropertyKey, any> | undefined {
  switch (context.getType<string>()) {
    case 'http':
      return context.switchToHttp().getRequest();
    case 'ws':
      return context.switchToWs().getClient();
    case 'rpc': {
      const ctx = context.switchToRpc().getContext();
      return typeof ctx === 'object' && ctx !== null ? ctx : undefined;
    }
    case 'graphql':
      return graphqlContextOf(context)?.req;
    case 'mcp':
    case 'ai': {
      const call = callContextOf(context);
      return call?.request ?? call;
    }
    default:
      return undefined;
  }
}

/**
 * Records what the handler sees (`@CurrentUser()`, `AuthContext`,
 * `request.user`). `perCallOnly` skips the carrier mirror; used for ws
 * `@Public()` messages, so they do not clear `client.user` under a
 * concurrent message on the same socket.
 */
export function setAuthState(context: ExecutionContext, result: State, { perCallOnly = false } = {}) {
  for (const key of callKeys(context)) {
    perCall.set(key, result);
  }

  const carrier = carrierOf(context);
  const type = context.getType<string>();
  if (carrier && (type === 'ws' || type === 'graphql')) {
    // A function of the call, not a user: safe on a carrier that other calls share.
    carrier[USER_OF] = userOf;
  }
  if (perCallOnly) {
    return;
  }

  const own = stateCarrierOf(context);
  if (own) {
    own[AUTH_STATE] = result;
  }
  if (!carrier) {
    return;
  }

  carrier.user = result?.user ?? null;
  // `request.session` is often another package's (express-session, @fastify/session): mirrored only
  // where it is free, or still holds what this package put there.
  if (!('session' in carrier) || carrier.session === carrier[MIRRORED_SESSION]) {
    carrier.session = result?.session ?? null;
    carrier[MIRRORED_SESSION] = carrier.session;
  }
}

/**
 * `undefined` when authentication has not run for this call, `null` when it
 * ran and the caller is anonymous.
 */
export function getAuthState(context: ExecutionContext): State | undefined {
  for (const key of callKeys(context)) {
    if (perCall.has(key)) {
      return perCall.get(key);
    }
  }

  const own = stateCarrierOf(context);
  return own && AUTH_STATE in own ? own[AUTH_STATE] : undefined;
}

/**
 * @internal This call's result: the scope the interceptor opened for it, else what the guard
 * recorded on the carrier. A ws message whose payload is a primitive shares nothing else with its
 * guard but the socket, which outlives it, and would otherwise read another message's user.
 */
export function resultOf(context: ExecutionContext): State | undefined {
  const scoped = scopedResult(context);
  return scoped !== undefined ? scoped : getAuthState(context);
}

/**
 * The user of one ws message or GraphQL operation, for other packages: they call
 * `carrier[USER_OF](context)` on a ws client, or on GraphQL's `context.req`, that this package
 * has recorded a result on. Both outlive the call: the client is the connection, and over
 * graphql-ws `context.req` is the socket's upgrade request. Their `user` is whatever the last
 * authenticated call left, and a `@Public()` call leaves it alone. This answers what
 * `@CurrentUser()` gets instead: the call's user, `null` when the call is anonymous (a `@Public()`
 * one is), and `undefined` when nothing was recorded, for the message or its connection. A GraphQL
 * operation records its own result, so one that recorded nothing authenticated nothing: `null`,
 * never the `user` another operation left on the `req` they share.
 */
function userOf(context: ExecutionContext): unknown {
  const result = resultOf(context);
  if (result === undefined) {
    return context.getType<string>() === 'graphql' ? null : undefined;
  }
  return result?.user ?? null;
}

const RAW = Symbol.for('nestjs.authentication.raw');
const rawPerCall = new WeakMap<object, State>();

/**
 * The providers' unfiltered answer, cached so a guard applied twice (global
 * plus `@UseGuards`, or GraphQL root and field resolvers sharing one
 * operation's context) authenticates once. Per message for ws, and per
 * operation for GraphQL: over graphql-ws one upgrade request serves every
 * operation of the socket, and each must see a revocation.
 */
export function setRawResult(context: ExecutionContext, result: State) {
  if (context.getType() === 'ws') {
    for (const key of callKeys(context)) {
      rawPerCall.set(key, result);
    }
    return;
  }

  const own = stateCarrierOf(context);
  if (own) {
    own[RAW] = result;
  }
}

export function getRawResult(context: ExecutionContext): State | undefined {
  if (context.getType() === 'ws') {
    for (const key of callKeys(context)) {
      if (rawPerCall.has(key)) {
        return rawPerCall.get(key);
      }
    }
    return undefined;
  }

  const own = stateCarrierOf(context);
  return own && RAW in own ? own[RAW] : undefined;
}

/**
 * Where a call's own state is kept, the providers' raw answer and the result
 * recorded for the handler: the GraphQL operation's context, else the call's
 * carrier. The context is built for each operation; its `req` is not, over
 * graphql-ws.
 */
function stateCarrierOf(context: ExecutionContext): Record<PropertyKey, any> | undefined {
  if (context.getType<string>() === 'graphql') {
    return graphqlContextOf(context);
  }
  return carrierOf(context);
}

/**
 * Request headers for the transports that have them:
 * - `http`: `request.headers`
 * - `ws`: socket.io's `client.handshake.headers`, else `client.request.headers`
 *   (`WsAuthenticator.authenticateConnection()` stores the upgrade request
 *   there for the `ws` library)
 * - `graphql`: `context.req.headers`
 * - `mcp`: the headers of the HTTP request the call arrived in; `undefined`
 *   over stdio, where the MCP spec takes credentials from the environment
 * - `rpc`: `undefined`; metadata is transport specific
 */
export function getRequestHeaders(context: ExecutionContext): Headers | undefined {
  return requestOf(context)?.headers;
}

/**
 * The request behind a call, as far as authentication needs it: headers,
 * and the method for HTTP, GraphQL, MCP and agent functions (a WebSocket
 * handshake has none, so it counts as a safe request). `undefined` for RPC,
 * for MCP over stdio, and for an agent function called in a job.
 */
export function requestOf(context: ExecutionContext): { headers: Headers; method?: string } | undefined {
  switch (context.getType<string>()) {
    case 'http':
      return context.switchToHttp().getRequest();
    case 'ws': {
      const client = context.switchToWs().getClient();
      const headers = client?.handshake?.headers ?? client?.request?.headers;
      return headers ? { headers } : undefined;
    }
    case 'graphql':
      return graphqlContextOf(context)?.req;
    case 'mcp':
    case 'ai': {
      const request = callContextOf(context)?.request;
      return request?.headers ? (request as { headers: Headers; method?: string }) : undefined;
    }
    default:
      return undefined;
  }
}

export function firstHeader(headers: Headers | undefined, name: string): string | undefined {
  const value = headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}
