export interface AuthenticationErrorOptions {
  /** `WWW-Authenticate` challenge sent with the 401 over HTTP, e.g. `ApiKey header="x-api-key"`. */
  challenge?: string;
  /**
   * Machine-readable reason (`mfa_required`), sent as the body's `code`
   * field, and as its `error` field, which carried it before `code` existed.
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
