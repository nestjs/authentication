import { Injectable, type OnApplicationShutdown } from '@nestjs/common';
import { Subject, type Observable } from 'rxjs';
import type { AuthenticationEvent } from './authentication-events.interface.js';
import { channelFor } from './authentication.channels.js';

/**
 * The audit trail of sign-ins, sign-outs, second-factor changes, password
 * resets, email verifications and refused magic links, and the session
 * activity a store failed to record. Each event is also
 * published on its `node:diagnostics_channel` channel
 * (`nestjs:authentication:<type>`), for tooling that runs outside Nest.
 * Listeners cannot change the outcome: a throwing channel subscriber is
 * reported on the next tick, not in the sign-in that emitted.
 */
@Injectable()
export class AuthenticationEvents implements OnApplicationShutdown {
  private readonly subject = new Subject<AuthenticationEvent>();
  /** Every event of this application, in order. */
  readonly events$: Observable<AuthenticationEvent> = this.subject.asObservable();

  /** @internal Called by the module's services. */
  emit(event: AuthenticationEvent): void {
    const target = channelFor(event.type);
    if (target.hasSubscribers) {
      target.publish(event);
    }
    this.subject.next(event);
  }

  onApplicationShutdown() {
    this.subject.complete();
  }
}
