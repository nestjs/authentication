import { ConflictException, ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import type { HttpAdapterHost } from '@nestjs/core';
import type { AuthenticationError } from '../errors/authentication.error.js';

type ErrorCtor = new (error: string | object) => Error;
const loaded = new Map<string, Promise<ErrorCtor | undefined>>();

/** Lazily loads an optional peer's exception class, once. */
function load(pkg: '@nestjs/websockets' | '@nestjs/microservices', name: string) {
  let pending = loaded.get(pkg);
  if (!pending) {
    pending = import(pkg).then(
      (mod: Record<string, unknown>) => mod[name] as ErrorCtor,
      () => undefined,
    );
    loaded.set(pkg, pending);
  }
  return pending;
}

export interface Refusal {
  /** Default 401. 403 for a user the route refuses (an unverified address), 409 for a conflict (`MfaAlreadyEnrolledError`). */
  status?: 401 | 403 | 409;
  /** Default `Unauthorized`. */
  message?: string;
  /** Machine-readable reason (`mfa_required`): the body's `code`, and its `error` as before `code` had its own key. */
  code?: string;
  /**
   * Keeps the code out of `error`, for a refusal whose body never had one
   * (the guard's `missing_credentials`): `code` alone tells it apart.
   */
  codeOnly?: boolean;
  /** Machine-readable data the app chose to send (`AuthenticationError`'s `details`): the body's `details`. */
  details?: Record<string, unknown>;
  /** The error behind the refusal, kept as the exception's `cause` for logs. */
  cause?: unknown;
}

const DEFAULT_MESSAGE = 'Unauthorized';

/** What Nest's exceptions put in `error` when there is no code. */
const PHRASES = { 401: 'Unauthorized', 403: 'Forbidden', 409: 'Conflict' } as const;

/** The refusal for an `AuthenticationError` a provider or a handler threw. */
export function refusalOf(error: AuthenticationError): Refusal {
  const { status, message, code, details } = error;
  return { status, message, code, details, cause: error };
}

/**
 * The one place this package's refusals become responses, for the guard and
 * for `AuthenticationError`s thrown by handlers: the error each transport's
 * exception filter understands, for the refusal's status.
 *
 * - HTTP and GraphQL: Nest's own `UnauthorizedException` (or
 *   `ForbiddenException` for a 403, `ConflictException` for a 409), with the
 *   body Nest gives it: `{"message":"Unauthorized","statusCode":401}`, or with
 *   a message, `{"message":"Refresh token reused","error":"Unauthorized","statusCode":401}`.
 *   A `code` is sent as `code`, and replaces the status phrase in `error`
 *   (unless `codeOnly`), as it did before it had its own key; `details` come
 *   last. Over HTTP, `challenge` becomes the `WWW-Authenticate` header of a 401.
 * - ws and rpc: a `WsException` / `RpcException` carrying
 *   `{ statusCode, message }` (plus `status: 'error'` for ws, and with a
 *   code, `error` unless `codeOnly`, then `code` and `details`). Those filters
 *   report `HttpException`s as "Internal server error", hence their own
 *   classes, loaded only when the packages are installed.
 *
 * Nothing else reaches the body: `cause` stays on the exception, for logs.
 */
export async function refusal(
  context: ExecutionContext,
  { status = 401, message = DEFAULT_MESSAGE, code, codeOnly, details, cause }: Refusal = {},
  { challenge, adapterHost }: { challenge?: string; adapterHost?: HttpAdapterHost } = {},
): Promise<Error> {
  const errorCode = codeOnly ? undefined : code;
  const extra = { ...(code && { code }), ...(details !== undefined && { details }) };

  switch (context.getType<string>()) {
    case 'ws': {
      const WsException = await load('@nestjs/websockets', 'WsException');
      if (WsException) {
        const payload = { status: 'error', statusCode: status, ...(errorCode && { error: errorCode }), message, ...extra };
        return withCause(new WsException(payload), cause);
      }
      break;
    }
    case 'rpc': {
      const RpcException = await load('@nestjs/microservices', 'RpcException');
      if (RpcException) {
        const payload = { statusCode: status, ...(errorCode && { error: errorCode }), message, ...extra };
        return withCause(new RpcException(payload), cause);
      }
      break;
    }
    case 'http':
      if (challenge && status === 401) {
        adapterHost?.httpAdapter?.setHeader(context.switchToHttp().getResponse(), 'WWW-Authenticate', challenge);
      }
      break;
  }

  // Key for key what `new UnauthorizedException(message, code)` gives: the
  // default 401 (`new UnauthorizedException()`) and an empty message have no
  // `error`, the others the code or the status phrase.
  const phrase = errorCode ?? PHRASES[status];
  const bare = !message || (status === 401 && message === DEFAULT_MESSAGE && !errorCode);
  const body = bare
    ? { message: message || phrase, statusCode: status, ...extra }
    : { message, error: phrase, statusCode: status, ...extra };

  const options = { cause };
  if (status === 409) {
    return new ConflictException(body, options);
  }
  if (status === 403) {
    return new ForbiddenException(body, options);
  }
  return new UnauthorizedException(body, options);
}

function withCause(error: Error, cause: unknown): Error {
  if (cause !== undefined) {
    error.cause = cause;
  }
  return error;
}
