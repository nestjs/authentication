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
  /**
   * Without one, Nest's bare body (`new UnauthorizedException()`): the status
   * phrase as `message`, and no `error`.
   */
  message?: string;
  /** Machine-readable reason (`mfa_required`): Nest's `errorCode`, and the body's `error` when there is a message. */
  code?: string;
  /** Machine-readable data the app chose to send (`AuthenticationError`'s `details`): the body's `details`. */
  details?: Record<string, unknown>;
  /** The error behind the refusal, kept as the exception's `cause` for logs. */
  cause?: unknown;
}

const DEFAULT_MESSAGE = 'Unauthorized';

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
 *   `ForbiddenException` for a 403, `ConflictException` for a 409), with
 *   Nest's own body: `{"message":"Unauthorized","statusCode":401}`, or with a
 *   message, `{"message":"Refresh token reused","error":"Unauthorized","statusCode":401}`.
 *   A `code` is Nest's `errorCode` (on the exception, and in the body), and
 *   the description in `error` when there is a message; `details` follow.
 *   Over HTTP, `challenge` becomes the `WWW-Authenticate` header of a 401.
 * - ws and rpc: a `WsException` / `RpcException` carrying
 *   `{ statusCode, message }` (plus `status: 'error'` for ws, and `error`,
 *   `errorCode` and `details` as above). Those filters report
 *   `HttpException`s as "Internal server error", hence their own classes,
 *   loaded only when the packages are installed.
 *
 * Nothing else reaches the body: `cause` stays on the exception, for logs.
 */
export async function refusal(
  context: ExecutionContext,
  { status = 401, message, code, details, cause }: Refusal = {},
  { challenge, adapterHost }: { challenge?: string; adapterHost?: HttpAdapterHost } = {},
): Promise<Error> {
  // The default message without a code gives the body of a bare `new UnauthorizedException()`.
  const bare = message === undefined || (status === 401 && message === DEFAULT_MESSAGE && !code);
  const payload = {
    statusCode: status,
    ...(!bare && code && { error: code }),
    message: message ?? PHRASES[status],
    ...(code && { errorCode: code }),
    ...(details !== undefined && { details }),
  };

  switch (context.getType<string>()) {
    case 'ws': {
      const WsException = await load('@nestjs/websockets', 'WsException');
      if (WsException) {
        return withCause(new WsException({ status: 'error', ...payload }), cause);
      }
      break;
    }
    case 'rpc': {
      const RpcException = await load('@nestjs/microservices', 'RpcException');
      if (RpcException) {
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

  const Exception = status === 409 ? ConflictException : status === 403 ? ForbiddenException : UnauthorizedException;
  // Nest builds the body: `error` is the code (the description) or the status phrase, then `errorCode`.
  const options = { cause, ...(code && { errorCode: code, ...(!bare && { description: code }) }) };
  const exception = new Exception(bare ? undefined : message, options);
  // `details` are not Nest's: its body, with them.
  return details === undefined ? exception : new Exception({ ...(exception.getResponse() as object), details }, options);
}

function withCause(error: Error, cause: unknown): Error {
  if (cause !== undefined) {
    error.cause = cause;
  }
  return error;
}
