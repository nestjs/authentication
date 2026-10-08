import { Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { HttpAdapterHost, Reflector } from '@nestjs/core';
import { hasVerifiedEmail } from '../account/email.util.js';
import { getRawResult, setAuthState, setRawResult } from '../utils/auth-state.util.js';
import { AuthenticationRegistry } from '../services/authentication-registry.service.js';
import type { CredentialProvider } from '../interfaces/authentication-registry.interface.js';
import { AUTHENTICATION_GUARD_BRAND, AUTHENTICATION_METADATA } from '../authentication.constants.js';
import type { RouteAuthentication } from '../interfaces/authenticate-options.interface.js';
import { AuthenticationError } from '../errors/authentication.error.js';
import { refusal, refusalOf, type Refusal } from '../utils/transport-errors.util.js';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';

type Provider = CredentialProvider<unknown, unknown>;

/** Which provider produced a result, for `@Authenticate({ providers })` on a cached result. */
const producedBy = new WeakMap<object, Provider>();

const MFA_REQUIRED: Refusal = { message: 'Second factor required', code: 'mfa_required' };
const EMAIL_UNVERIFIED: Refusal = { status: 403, message: 'Email address not verified', code: 'email_unverified' };
/** No provider recognised any credentials. `code` only: this body never had an `error`. */
const MISSING_CREDENTIALS: Refusal = { code: 'missing_credentials', codeOnly: true };

/**
 * Runs the registered providers in order and records the first result on
 * the call.
 *
 * | Route | No credentials | Valid | Invalid |
 * | --- | --- | --- | --- |
 * | default | 401 `missing_credentials` | pass | 401 |
 * | `@Authenticate({ optional: true })` | pass, user `null` | pass | 401 |
 * | `@Public()` | providers not called | not called | not called |
 *
 * A result with `mfa: 'pending'` (second factor outstanding) does not count
 * as signed in: 401 `mfa_required` where a user is required, anonymous on
 * optional routes. `@Authenticate({ mfa: true })` needs `mfa: 'verified'`,
 * and `@Authenticate({ verifiedEmail: true })` a verified address (403
 * `email_unverified`). The code is the body's `code`; a provider's
 * `AuthenticationError` is answered with its own `code` and `details`.
 *
 * Providers run once per call: the raw result is cached on the request, the
 * GraphQL operation's context, or per ws message. With
 * `@Authenticate({ providers })`, a cached result from another provider is
 * ignored.
 *
 * Where Nest runs no global guard, neither does this one: on GraphQL field
 * resolvers (`@ResolveField`), unless the GraphQL module sets
 * `fieldResolverEnhancers: ['guards']`, and on the message handlers of a
 * hybrid app, unless it connects them with
 * `app.connectMicroservice(options, { inheritAppConfig: true })`. There,
 * route options are not enforced.
 */
@Injectable()
export class AuthenticationGuard implements CanActivate {
  /**
   * How `@nestjs/authorization` recognizes this guard, subclasses included,
   * whatever their names: it fails at startup when this guard would run
   * after its own.
   */
  static readonly [AUTHENTICATION_GUARD_BRAND] = true;

  constructor(
    private readonly reflector: Reflector,
    private readonly adapterHost: HttpAdapterHost,
    private readonly registry: AuthenticationRegistry,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const route = this.route(context);
    if (route.public) {
      // Nothing is written for http/graphql/rpc (another resolver of the same
      // GraphQL operation may need the user); ws marks just this message.
      if (context.getType() === 'ws') {
        setAuthState(context, null, { perCallOnly: true });
      }
      return true;
    }

    const only = route.providers;
    const all = this.registry.providers;
    const providers = only ? all.filter((p) => only.some((type) => p instanceof type)) : all;

    let raw = getRawResult(context);
    if (only && raw && !providers.includes(producedBy.get(raw)!)) {
      raw = undefined;
    }
    if (raw === undefined) {
      raw = await this.authenticate(context, providers, !only);
      // A restricted run does not speak for the other routes sharing the carrier.
      if (!only) {
        setRawResult(context, raw);
      }
    }

    const pending = raw?.mfa === 'pending';
    const result = pending ? null : raw;
    if (!result) {
      if (route.optional) {
        setAuthState(context, null);
        return true;
      }
      if (!only) {
        this.forgetConnection(context);
      }
      if (pending) {
        return this.fail(context, MFA_REQUIRED);
      }
      return this.fail(context, MISSING_CREDENTIALS, this.challenges(context, providers));
    }

    if (route.mfa && result.mfa !== 'verified') {
      return this.fail(context, MFA_REQUIRED);
    }

    if (route.verifiedEmail) {
      const handler = this.registry.handler('emailVerification');
      const verified = handler?.isVerified ? await handler.isVerified(result.user) : hasVerifiedEmail(result.user);
      if (!verified) {
        return this.fail(context, EMAIL_UNVERIFIED);
      }
    }

    setAuthState(context, result);
    return true;
  }

  /** Class options with the method's merged over them, field by field. */
  private route(context: ExecutionContext): RouteAuthentication {
    return {
      ...this.reflector.get<RouteAuthentication | undefined>(AUTHENTICATION_METADATA, context.getClass()),
      ...this.reflector.get<RouteAuthentication | undefined>(AUTHENTICATION_METADATA, context.getHandler()),
    };
  }

  private async authenticate(
    context: ExecutionContext,
    providers: readonly Provider[],
    everyProvider: boolean,
  ): Promise<AuthenticationResult<unknown, unknown> | null> {
    for (const provider of providers) {
      try {
        const result = await provider.authenticate(context);
        if (result?.user) {
          producedBy.set(result, provider);
          return result;
        }
      } catch (error) {
        if (error instanceof AuthenticationError) {
          if (everyProvider || error.status === 401) {
            this.forgetConnection(context);
          }
          return this.fail(context, refusalOf(error), error.challenge);
        }
        throw error; // a store outage is a 500, not a 401
      }
    }
    return null;
  }

  /**
   * A ws socket keeps its last user (`client.user`) for code that reads it on
   * messages that run no provider (`@Public()`): a message refused for its
   * credentials says the connection has none now, its session revoked or its
   * token expired. `@nestjs/authorization` asks for each message's own user
   * instead (`userOf` in auth-state.util.ts).
   */
  private forgetConnection(context: ExecutionContext) {
    if (context.getType() === 'ws') {
      setAuthState(context, null);
    }
  }

  private challenges(context: ExecutionContext, providers: readonly Provider[]): string | undefined {
    // Once each: a JWT and an API key provider in one realm accept the same `Bearer realm="…"`.
    const list = new Set(providers.map((p) => p.challenge?.(context)).filter((c): c is string => !!c));
    return [...list].join(', ') || undefined;
  }

  private async fail(context: ExecutionContext, reason: Refusal, challenge?: string): Promise<never> {
    throw await refusal(context, reason, { challenge, adapterHost: this.adapterHost });
  }
}
