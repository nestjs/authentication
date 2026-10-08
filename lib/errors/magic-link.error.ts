import { AuthenticationError } from './authentication.error.js';

/**
 * A link was presented in a browser other than the one that requested it
 * (see `magicLink.bindToBrowser`). The one refusal `consume()` tells
 * apart: the customer can act on it (open the link where they asked for
 * it, or request a new one here), and it is decided before the link is
 * looked up, so it reveals nothing about the token. Unknown, used, expired
 * and refused links share one answer, `null`.
 *
 * An `AuthenticationError`: a route that lets it escape answers 401 on any
 * transport, with `not_this_browser` as the body's `errorCode` (and `error`), the way
 * `TokenService.issue()` answers `mfa_required`.
 */
export class MagicLinkError extends AuthenticationError {
  /** Why the link was refused: the only reason apps are told. */
  readonly reason = 'not-this-browser' as const;

  constructor() {
    super('Open the link in the browser you requested it from, or request a new one here', { code: 'not_this_browser' });
    this.name = 'MagicLinkError';
  }
}
