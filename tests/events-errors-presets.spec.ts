/**
 * The small public pieces: `AuthenticationEvents` and its diagnostics channels, the error classes'
 * fields, and the OAuth/OIDC provider presets (GitHub's profile mapping in particular).
 */
import { channel, subscribe, unsubscribe } from 'node:diagnostics_channel';
import {
  AuthenticationError,
  AuthenticationEvents,
  JwtError,
  MagicLinkError,
  RefreshTokenError,
  github,
  google,
  microsoft,
  type AuthenticationEvent,
} from '../lib/index.js';
import { channelFor } from '../lib/events/authentication.channels.js';
import { OidcError } from '../lib/errors/oidc.error.js';
import { SecretDecryptionError } from '../lib/errors/secret-decryption.error.js';

describe('AuthenticationEvents', () => {
  it('publishes each event on events$ in order, and on the channel of its own type only', () => {
    const events = new AuthenticationEvents();
    const seen: AuthenticationEvent[] = [];
    events.events$.subscribe((event) => seen.push(event));
    const signIns: unknown[] = [];
    const signOuts: unknown[] = [];
    const onSignIn = (message: unknown) => signIns.push(message);
    const onSignOut = (message: unknown) => signOuts.push(message);
    subscribe('nestjs:authentication:sign-in', onSignIn);
    subscribe('nestjs:authentication:sign-out', onSignOut);

    try {
      const signIn: AuthenticationEvent = { type: 'sign-in', userId: 'u1', sessionId: 's1' };
      const disabled: AuthenticationEvent = { type: 'mfa-disabled', userId: 'u1' };
      events.emit(signIn);
      events.emit(disabled);

      expect(seen).toEqual([signIn, disabled]);
      expect(signIns).toEqual([signIn]);
      expect(signIns[0]).toBe(signIn); // the event itself, not a copy
      expect(signOuts).toEqual([]);
    } finally {
      unsubscribe('nestjs:authentication:sign-in', onSignIn);
      unsubscribe('nestjs:authentication:sign-out', onSignOut);
    }
  });

  it('names one channel per type, the one node:diagnostics_channel returns for that name', () => {
    expect(channelFor('password-reset')).toBe(channelFor('password-reset'));
    expect(channelFor('password-reset')).toBe(channel('nestjs:authentication:password-reset'));
    expect(channelFor('password-reset')).not.toBe(channelFor('email-verified'));
  });

  it('completes events$ on shutdown, and keeps separate apps apart', () => {
    const one = new AuthenticationEvents();
    const other = new AuthenticationEvents();
    const seen: string[] = [];
    let completed = false;
    one.events$.subscribe({ next: (event) => seen.push(`one:${event.type}`), complete: () => (completed = true) });
    other.events$.subscribe((event) => seen.push(`other:${event.type}`));

    other.emit({ type: 'mfa-disabled', userId: 'u1' });
    one.onApplicationShutdown();
    one.emit({ type: 'mfa-disabled', userId: 'u1' });

    expect(completed).toBe(true);
    expect(seen).toEqual(['other:mfa-disabled']);
  });
});

describe('error classes', () => {
  it('AuthenticationError has a challenge, a code and a cause only when given', () => {
    const bare = new AuthenticationError();
    expect(bare.message).toBe('Unauthorized');
    expect([bare.challenge, bare.code]).toEqual([undefined, undefined]);
    expect('cause' in bare).toBe(false);

    const cause = new Error('signature mismatch');
    const full = new AuthenticationError('Bad key', { challenge: 'ApiKey', code: 'bad_key', cause });
    expect(full).toMatchObject({ message: 'Bad key', challenge: 'ApiKey', code: 'bad_key', cause, status: 401 });
  });

  it('names a subclass after itself, without a constructor of its own', () => {
    class ApiKeyRevokedError extends AuthenticationError {}
    const error = new ApiKeyRevokedError('revoked');
    expect(error.name).toBe('ApiKeyRevokedError');
    expect(error).toBeInstanceOf(AuthenticationError);
    expect(String(error)).toBe('ApiKeyRevokedError: revoked');
  });

  it('RefreshTokenError says why, in its message and its reason', () => {
    for (const reason of ['invalid', 'expired', 'reused'] as const) {
      expect(new RefreshTokenError(reason)).toMatchObject({ reason, message: `Refresh token ${reason}`, name: 'RefreshTokenError' });
    }
  });

  it('MagicLinkError tells the customer what to do, and nothing about the token', () => {
    expect(new MagicLinkError()).toMatchObject({
      reason: 'not-this-browser',
      message: 'Open the latest link in the browser you requested it from, or request a new one here',
    });
    expect(new JwtError('token expired').code).toBeUndefined();
  });

  it('OIDC and decryption failures are not AuthenticationErrors: they are not the caller’s fault', () => {
    const oidc = new OidcError('IdP down', 'unavailable');
    expect(oidc).toMatchObject({ name: 'OidcError', kind: 'unavailable', message: 'IdP down' });
    expect(oidc).not.toBeInstanceOf(AuthenticationError);

    const decryption = new SecretDecryptionError('unknown key id');
    expect(decryption.name).toBe('SecretDecryptionError');
    expect(decryption).not.toBeInstanceOf(AuthenticationError);
  });
});

describe('provider presets', () => {
  const credentials = { clientId: 'id', clientSecret: 'secret' };

  it('google() and microsoft() are OIDC issuers with the credentials', () => {
    expect(google(credentials)).toEqual({ issuer: 'https://accounts.google.com', clientId: 'id', clientSecret: 'secret' });
    expect(microsoft({ tenant: '0b6a3f5e-1111-2222-3333-444455556666', ...credentials })).toEqual({
      issuer: 'https://login.microsoftonline.com/0b6a3f5e-1111-2222-3333-444455556666/v2.0',
      ...credentials,
    });
    for (const tenant of ['organizations', 'consumers']) {
      expect(() => microsoft({ tenant, ...credentials })).toThrow(`microsoft(): pass the tenant id, a GUID (Entra admin center, Overview), not "${tenant}"`);
    }
  });

  describe('github()', () => {
    const preset = github(credentials);
    const profileOf = (user: unknown, emails: unknown) => {
      const fetchJson = vi.fn(async () => emails);
      const result = preset.profile!.call(preset, user, { provider: 'github', tokens: {} as never, fetchJson });
      return { result: Promise.resolve(result), fetchJson };
    };

    it('is plain OAuth 2.0 asking for the profile and the addresses', () => {
      expect(preset).toMatchObject({
        kind: 'oauth2',
        authorizationEndpoint: 'https://github.com/login/oauth/authorize',
        tokenEndpoint: 'https://github.com/login/oauth/access_token',
        userinfoEndpoint: 'https://api.github.com/user',
        scopes: ['read:user', 'user:email'],
        clientId: 'id',
      });
    });

    it('takes the primary verified address from /user/emails, never the public profile’s', async () => {
      const user = { id: 42, login: 'octocat', name: 'The Octocat', avatar_url: 'https://avatars.test/42', email: 'public@evil.test' };
      const { result, fetchJson } = profileOf(user, [
        { email: 'old@example.com', primary: false, verified: true },
        { email: 'octo@example.com', primary: true, verified: true },
      ]);

      await expect(result).resolves.toEqual({
        provider: 'github',
        subject: '42',
        email: 'octo@example.com',
        emailVerified: true,
        name: 'The Octocat',
        picture: 'https://avatars.test/42',
        claims: user,
      });
      expect(fetchJson).toHaveBeenCalledWith('https://api.github.com/user/emails');
    });

    it('gives no address when the primary one is unverified, or the list is not a list', async () => {
      for (const emails of [[{ email: 'octo@example.com', primary: true, verified: false }], { message: 'Not Found' }, null]) {
        await expect(profileOf({ id: 1, login: 'octocat' }, emails).result).resolves.toMatchObject({
          email: undefined,
          emailVerified: false,
          name: 'octocat', // no display name: the login
        });
      }
    });

    it('refuses a user without an id, before any further request', async () => {
      for (const user of [{ login: 'octocat' }, { id: null }, null]) {
        const { result, fetchJson } = profileOf(user, []);
        await expect(result).rejects.toThrow('unexpected GitHub user');
        expect(fetchJson).not.toHaveBeenCalled();
      }
    });
  });
});
