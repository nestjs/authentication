import type { PasskeyFailure } from '../interfaces/passkey.interface.js';
import { AuthenticationError } from './authentication.error.js';

/**
 * A registration `PasskeyService.verifyRegistration()` refused. An
 * `AuthenticationError`: a route that lets it escape answers 401 with
 * `passkey_refused` as the body's `errorCode`; `reason` says why, for logs.
 */
export class PasskeyError extends AuthenticationError {
  constructor(readonly reason: PasskeyFailure) {
    super(`Passkey refused: ${reason}`, { code: 'passkey_refused' });
    this.name = 'PasskeyError';
  }
}
