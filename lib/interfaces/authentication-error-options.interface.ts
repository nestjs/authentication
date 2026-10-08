export interface AuthenticationErrorOptions {
  /** `WWW-Authenticate` challenge sent with the 401 over HTTP, e.g. `ApiKey header="x-api-key"`. */
  challenge?: string;
  /**
   * Machine-readable reason (`mfa_required`), sent as Nest's `errorCode`
   * (the HTTP exception's `errorCode`, and the body's on every transport),
   * and as the body's `error` field, which carried it first.
   */
  code?: string;
  /**
   * Machine-readable data for the client, sent as the body's `details` field
   * as is (`{ retryAfter: 30 }`): keep it JSON-serialisable, and leave out
   * anything the caller should not see. Not sent unless set.
   */
  details?: Record<string, unknown>;
  /** The error behind this one, for logs. Never sent. */
  cause?: unknown;
}
