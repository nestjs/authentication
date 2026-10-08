import type { AuthenticationErrorOptions } from '../interfaces/authentication-error-options.interface.js';

/**
 * The base class of this package's errors, and on its own the error for
 * credentials that are missing or failed verification: a 401 on every
 * transport.
 *
 * - Thrown by a provider, the guard answers with it and sends `challenge`
 *   as the `WWW-Authenticate` header.
 * - Thrown by a handler or anything it calls (`requireUser()`, a failed
 *   `TokenService.refresh()`), the module's interceptor turns it into the
 *   transport's error for its `status`: an HTTP 401 (409 for
 *   `MfaAlreadyEnrolledError`), GraphQL `UNAUTHENTICATED`, a `WsException`
 *   or an `RpcException`. Its `code` is sent as the body's `errorCode`
 *   (and `error`), its `details` as `details`.
 * - Elsewhere (a queue worker), it is a plain `Error`.
 */
export class AuthenticationError extends Error {
  /**
   * 401, or 409 for `MfaAlreadyEnrolledError`: the caller's fault, not an
   * outage, so other packages classify it without importing this class
   * (`@nestjs/resilience` neither retries it nor counts it against a
   * circuit breaker).
   */
  readonly status: 401 | 403 | 409 = 401;
  readonly challenge?: string;
  readonly code?: string;
  readonly details?: Record<string, unknown>;

  constructor(message = 'Unauthorized', { challenge, code, details, cause }: AuthenticationErrorOptions = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = new.target.name;

    if (challenge !== undefined) {
      this.challenge = challenge;
    }
    if (code !== undefined) {
      this.code = code;
    }
    if (details !== undefined) {
      this.details = details;
    }
  }
}
