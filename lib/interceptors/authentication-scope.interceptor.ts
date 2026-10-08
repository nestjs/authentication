import { Injectable, type CallHandler, type ExecutionContext, type NestInterceptor } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { catchError, from, mergeMap, Observable, throwError } from 'rxjs';
import { getAuthState } from '../utils/auth-state.util.js';
import { AuthenticationError } from '../errors/authentication.error.js';
import { refusal, refusalOf } from '../utils/transport-errors.util.js';
import { AuthenticationScope, runCall, type Scope } from '../context/authentication-scope.service.js';

/**
 * @internal Opens the scope with what the guard recorded, around the
 * subscription to `next.handle()`, not just the call: an inner interceptor
 * may call its own `next.handle()` only when it is subscribed, and again per
 * attempt (`@nestjs/resilience` retries), and the handler runs in the async
 * context of that call. Subscribing inside `run()` covers every such call,
 * pipes, the handler and everything they await. An `AuthenticationError`
 * escaping the handler becomes the transport's error for its status (a 401,
 * or a 409).
 */
@Injectable()
export class AuthenticationScopeInterceptor implements NestInterceptor {
  constructor(
    private readonly scope: AuthenticationScope,
    private readonly adapterHost: HttpAdapterHost,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const scope: Scope = { result: getAuthState(context) ?? null, context };

    return new Observable<unknown>((subscriber) =>
      this.scope.run(scope, () => runCall(scope, () => next.handle().subscribe(subscriber))),
    ).pipe(
      catchError((error: unknown) => {
        if (!(error instanceof AuthenticationError)) {
          return throwError(() => error);
        }

        const mapped = refusal(context, refusalOf(error), { challenge: error.challenge, adapterHost: this.adapterHost });
        return from(mapped).pipe(mergeMap((exception) => throwError(() => exception)));
      }),
    );
  }
}
