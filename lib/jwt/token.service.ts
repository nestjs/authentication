import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { TOKEN_PATTERN, randomToken, sha256 } from '../utils/crypto.util.js';
import { durationOr, hasExpired } from '../utils/duration.util.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AuthenticationError } from '../errors/authentication.error.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import { requireOption } from '../utils/options.util.js';
import { MfaService } from '../mfa/mfa.service.js';
import type { JwtSignerOptions } from '../interfaces/jwt-options.interface.js';
import { RefreshTokenError } from '../errors/refresh-token.error.js';
import type { RefreshTokenOptions } from '../interfaces/refresh-token-options.interface.js';
import type { RefreshTokenRecord } from '../interfaces/refresh-token-store.interface.js';
import type { IssueTokensOptions, TokenPair } from '../interfaces/token.interface.js';
import { MFA_AMR_VALUES } from './amr.util.js';
import { JwtSigner } from './jwt-signer.service.js';

/**
 * Tokens for clients that do not keep cookies (mobile apps, CLIs): a
 * short-lived JWT access token, and an opaque refresh token that renews it.
 *
 * - `issue()` is to token clients what `SignInService.signIn()` is to
 *   browsers: with `mfa` configured, a user with a confirmed authenticator gets no tokens without
 *   a second factor.
 * - Access tokens are signed with the module's `accessToken` options, the
 *   same ones `JwtBearerProvider` verifies with by default.
 * - Refresh tokens are single use and stored hashed. Each rotation stays in
 *   the family of the original sign-in, which has an absolute lifetime.
 * - Presenting a refresh token that was already rotated, including two
 *   concurrent presentations (`markRefreshTokenUsed()` is a compare-and-set), means two
 *   parties hold it: the whole family is revoked, and both have to sign in
 *   again (OAuth 2.0 Security BCP §4.14.2).
 */
@Injectable()
export class TokenService {
  private static readonly logger = new Logger('TokenService');
  /** The `amr` warning is a misconfiguration: once per process says enough. */
  private static warnedAmr = false;
  private readonly signer?: JwtSigner;
  private readonly expiresIn: number;
  private readonly ttl: number;
  private readonly absoluteTtl: number;
  private readonly clock?: () => number;

  constructor(
    private readonly storage: AuthenticationStorage,
    @Optional()
    @Inject(AUTHENTICATION_MODULE_OPTIONS)
    options?: { accessToken?: JwtSignerOptions; refreshToken?: RefreshTokenOptions },
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
    private readonly mfa: MfaService = new MfaService(storage),
  ) {
    const refresh = options?.refreshToken ?? {};
    this.ttl = durationOr(refresh.ttl, '30d');
    this.absoluteTtl = durationOr(refresh.absoluteTtl, '90d');
    this.clock = refresh.now;

    // A bad key fails at startup, not at the first sign-in.
    if (options?.accessToken) {
      requireOption(options.accessToken.key, 'accessToken.key', 'a secret of at least 32 bytes or a KeyObject');
      try {
        this.signer = new JwtSigner(options.accessToken);
      } catch (error) {
        throw new TypeError(`AuthenticationModule: \`accessToken\`: ${(error as Error).message.replace(/^JwtSigner: /, '')}`);
      }
    }

    this.expiresIn = Math.floor(durationOr(options?.accessToken?.ttl, '15m') / 1000);
  }

  /**
   * At sign-in: signs an access token and starts a refresh-token family.
   *
   * With `mfa` configured, a user with a confirmed authenticator must send a second factor
   * (`secondFactor`). Without one, `issue()` throws an
   * `AuthenticationError` whose body says `mfa_required`, and counts
   * nothing against the user's lockout; with a wrong one, `Invalid code`.
   * A verified second factor adds `mfa` to the `amr` claim, which
   * `@Authenticate({ mfa: true })` accepts; `claims.amr` cannot (see
   * {@link IssueTokensOptions.claims}).
   */
  async issue(userId: string, { claims, method, secondFactor }: IssueTokensOptions = {}): Promise<TokenPair> {
    const signer = this.requireSigner();
    const verified = await this.checkSecondFactor(userId, secondFactor);
    const own = this.ownClaims(claims);
    const familyClaims = verified ? { ...own, amr: [...(own?.amr ?? []), 'mfa'] } : own;
    const familyExpiresAt = new Date(this.now() + this.absoluteTtl);
    const { token, record } = await this.create(userId, randomToken(16), familyExpiresAt, familyClaims);

    this.events.emit({
      type: 'sign-in',
      userId,
      tokenFamilyId: record.familyId,
      ...(method && { method }),
      ...(verified && { mfa: 'verified' as const }),
    });

    return this.pair(signer, token, record);
  }

  /**
   * Spends a refresh token: returns its successor, and an access token with
   * the family's claims. Throws {@link RefreshTokenError} (`invalid`,
   * `expired`, `reused`), which a route answers with 401.
   */
  async refresh(refreshToken: string): Promise<TokenPair> {
    const signer = this.requireSigner();
    if (typeof refreshToken !== 'string' || !TOKEN_PATTERN.test(refreshToken)) {
      throw new RefreshTokenError('invalid');
    }

    const store = this.storage.refreshTokens;
    const record = await store.getRefreshToken(sha256(refreshToken));
    if (!record || (await store.isRefreshTokenFamilyRevoked(record.familyId))) {
      throw new RefreshTokenError('invalid');
    }

    const now = new Date(this.now());
    const expired = hasExpired(record.expiresAt, now.getTime()) || hasExpired(record.familyExpiresAt, now.getTime());
    // An unspent token that expired is refused as such, and not spent: presenting it
    // again is a client retrying, not theft. A spent one stays a reuse, expired or not.
    if (expired && !record.usedAt) {
      throw new RefreshTokenError('expired');
    }
    if (record.usedAt) {
      throw await this.reused(record);
    }

    // The successor is saved before this token is spent: a store that fails in between leaves it
    // unspent, so the client's retry is a retry, not a theft that signs the user out. If another
    // request spent it first, revoking the family revokes this successor too.
    const next = await this.create(record.userId, record.familyId, record.familyExpiresAt, record.claims);
    if (!(await store.markRefreshTokenUsed(record.id, now))) {
      throw await this.reused(record);
    }
    return this.pair(signer, next.token, next.record);
  }

  /** Two parties hold the token: the family is revoked, and the theft reported. */
  private async reused(record: RefreshTokenRecord): Promise<RefreshTokenError> {
    await this.storage.refreshTokens.revokeRefreshTokenFamily(record.familyId);
    this.events.emit({ type: 'refresh-token-reused', userId: record.userId, tokenFamilyId: record.familyId });
    return new RefreshTokenError('reused');
  }

  /**
   * Signs out the client holding `refreshToken` (one device): revokes its
   * family. Spent tokens of the family work too. Resolves `false` for
   * unknown or malformed tokens, which a route should not reveal (RFC 7009
   * §2.2). Throws without `accessToken`, as `refresh()` does.
   */
  async revoke(refreshToken: string): Promise<boolean> {
    this.requireSigner();
    if (typeof refreshToken !== 'string' || !TOKEN_PATTERN.test(refreshToken)) {
      return false;
    }

    const store = this.storage.refreshTokens;
    const record = await store.getRefreshToken(sha256(refreshToken));
    if (!record) {
      return false;
    }

    await store.revokeRefreshTokenFamily(record.familyId);
    this.events.emit({ type: 'sign-out', userId: record.userId, tokenFamilyId: record.familyId });
    return true;
  }

  /**
   * Signs the user out of every token client. Issued access tokens live
   * until they expire. Without `accessToken`, this app issues no refresh
   * tokens, and there is nothing to revoke: the store is not read. Apps that
   * share a user database configure `accessToken` in all of them if any of
   * them issues tokens: otherwise this one's sign-outs everywhere leave the
   * token clients of the others signed in.
   */
  async revokeAll(userId: string): Promise<void> {
    if (!this.signer) {
      return;
    }
    await this.storage.refreshTokens.revokeUserRefreshTokens(userId);
  }

  /** `true` when a second factor was required and verified; throws when one is required and missing or wrong. */
  private async checkSecondFactor(userId: string, secondFactor: IssueTokensOptions['secondFactor']): Promise<boolean> {
    if (!(await this.mfa.isEnrolled(userId))) {
      return false;
    }

    const { code, recoveryCode } = secondFactor ?? {};
    if (!code && !recoveryCode) {
      throw new AuthenticationError('Second factor required', { code: 'mfa_required' });
    }

    const verified = recoveryCode
      ? await this.mfa.verifyRecoveryCode(userId, recoveryCode)
      : await this.mfa.verifyTotp(userId, code!);
    if (!verified) {
      throw new AuthenticationError('Invalid code', { code: 'mfa_required' });
    }
    return true;
  }

  private pair(signer: JwtSigner, refreshToken: string, record: RefreshTokenRecord): TokenPair {
    const accessToken = signer.sign({ ...record.claims, sub: record.userId });
    return { accessToken, refreshToken, expiresIn: this.expiresIn };
  }

  private requireSigner(): JwtSigner {
    if (!this.signer) {
      throw new Error('TokenService: configure `accessToken` (the signing key) in the AuthenticationModule options');
    }
    return this.signer;
  }

  private async create(userId: string, familyId: string, familyExpiresAt: Date, claims?: Record<string, unknown>) {
    const token = randomToken();
    const now = this.now();
    const record: RefreshTokenRecord = {
      id: sha256(token),
      familyId,
      userId,
      createdAt: new Date(now),
      expiresAt: new Date(Math.min(now + this.ttl, familyExpiresAt.getTime())),
      familyExpiresAt,
      ...(claims && { claims }),
    };

    await this.storage.refreshTokens.saveRefreshToken(record);
    return { token, record };
  }

  /**
   * The app's claims with `amr` deduplicated and stripped of the values that
   * mean a second factor: `JwtBearerProvider` would take them as verified,
   * and only `issue()` knows whether a code was. An `amr` left empty is
   * dropped. The first token issued with such values logs a warning.
   */
  private ownClaims(claims: Record<string, unknown> | undefined): (Record<string, unknown> & { amr?: unknown[] }) | undefined {
    if (!claims || !Array.isArray(claims.amr)) {
      return claims;
    }

    const { amr, ...rest } = claims;
    const unique = [...new Set(amr)];
    const stripped = unique.filter((method) => MFA_AMR_VALUES.includes(method as string));
    if (stripped.length && !TokenService.warnedAmr) {
      TokenService.warnedAmr = true;
      TokenService.logger.warn(
        `issue() dropped ${stripped.map((m) => `'${m}'`).join(', ')} from \`claims.amr\`: those values mean a verified second ` +
          'factor, which only the service records (`mfa`, once a code was verified). Remove them from the claims passed to issue().',
      );
    }

    const kept = unique.filter((method) => !stripped.includes(method));
    return kept.length ? { ...rest, amr: kept } : rest;
  }

  private now() {
    return this.clock?.() ?? Date.now();
  }
}
