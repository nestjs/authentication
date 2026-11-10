import { Inject, Injectable, Optional } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { PasskeyError } from '../errors/passkey.error.js';
import type {
  PasskeyChallengeRecord,
  PasskeyRecord,
} from '../interfaces/passkey-store.interface.js';
import type {
  PasskeyAuthenticationOptions,
  PasskeyAuthenticationResponse,
  PasskeyDescriptor,
  PasskeyOptions,
  PasskeyRegistrationOptions,
  PasskeyRegistrationResponse,
  PasskeyUser,
} from '../interfaces/passkey.interface.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { randomToken, safeEqual, sha256 } from '../utils/crypto.util.js';
import { durationOr, hasExpired } from '../utils/duration.util.js';
import { requireUrlOption } from '../utils/options.util.js';
import {
  COSE_ALGORITHMS,
  FLAG_BE,
  FLAG_BS,
  FLAG_UP,
  FLAG_UV,
  cborDecode,
  coseToSpki,
  parseAuthenticatorData,
  verifyAssertion,
} from './webauthn.util.js';

/** WebAuthn caps a user handle at 64 bytes. */
const MAX_USER_HANDLE = 64;
const MAX_CREDENTIAL_ID = 1_023;

/**
 * Passkeys (WebAuthn) as a first factor, on `node:crypto` alone: attestation
 * `none`, and ES256, RS256 and EdDSA credentials. Checks the challenge, the
 * origin, the relying party id hash, the user presence and verification
 * flags, the signature and the sign counter.
 *
 * Each challenge is consumed once, which is what stops concurrent
 * assertions. The counter only catches a cloned authenticator when the
 * authenticator has one: synced passkeys (iCloud Keychain, Google Password
 * Manager) report 0 forever, and a counter that stays 0 is accepted.
 *
 * Registering needs a signed-in user: the caller passes the user it
 * authenticated. `verifyAuthentication()` proves who holds a passkey; the
 * caller then signs that user in.
 */
@Injectable()
export class PasskeyService {
  private readonly options?: PasskeyOptions;
  private readonly ttl: number;
  private readonly userVerification: 'required' | 'preferred' | 'discouraged';

  constructor(
    private readonly storage: AuthenticationStorage,
    @Optional()
    @Inject(AUTHENTICATION_MODULE_OPTIONS)
    options?: { passkey?: PasskeyOptions },
  ) {
    this.options = options?.passkey;
    if (this.options) {
      const { rpId, rpName, origins } = this.options;
      if (!rpId || !rpName || !Array.isArray(origins) || origins.length === 0) {
        throw new TypeError(
          'passkey: `rpId`, `rpName` and a non-empty `origins` are required',
        );
      }
      for (const origin of origins) {
        requireUrlOption(
          origin,
          'passkey.origins',
          'an origin such as https://app.example.com',
        );
      }
    }
    this.ttl = durationOr(this.options?.timeout, '5m');
    this.userVerification = this.options?.userVerification ?? 'preferred';
  }

  /** The options for `navigator.credentials.create()`; the user's existing passkeys are excluded. */
  async registrationOptions(
    user: PasskeyUser,
  ): Promise<PasskeyRegistrationOptions> {
    const options = this.feature();
    const handle = Buffer.from(user.id, 'utf8');
    if (handle.length === 0 || handle.length > MAX_USER_HANDLE) {
      throw new TypeError(
        `PasskeyService: the user id must be 1 to ${MAX_USER_HANDLE} bytes`,
      );
    }

    const challenge = await this.challenge('registration', user.id);
    const existing = await this.storage.passkeys.listUserPasskeys(user.id);
    return {
      rp: { id: options.rpId, name: options.rpName },
      user: {
        id: handle.toString('base64url'),
        name: user.name,
        displayName: user.displayName ?? user.name,
      },
      challenge,
      pubKeyCredParams: Object.values(COSE_ALGORITHMS).map((alg) => ({
        type: 'public-key',
        alg,
      })),
      timeout: this.ttl,
      attestation: 'none',
      excludeCredentials: existing.map(descriptor),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: this.userVerification,
      },
    };
  }

  /** Verifies what `create()` returned for `userId`, and saves the passkey. Throws {@link PasskeyError}. */
  async verifyRegistration(
    userId: string,
    response: PasskeyRegistrationResponse,
  ): Promise<PasskeyRecord> {
    const options = this.feature();
    const { challenge, clientData } = await this.takeChallenge(
      response,
      'webauthn.create',
      'registration',
    );
    if (challenge.userId !== userId) {
      throw new PasskeyError('user');
    }
    this.checkOrigin(clientData);

    let attestation: unknown;
    try {
      attestation = cborDecode(
        decode(response.response?.attestationObject),
      ).value;
    } catch {
      throw new PasskeyError('malformed');
    }
    const fmt = attestation instanceof Map ? attestation.get('fmt') : undefined;
    const authData =
      attestation instanceof Map ? attestation.get('authData') : undefined;
    if (!Buffer.isBuffer(authData)) {
      throw new PasskeyError('malformed');
    }
    // Browsers replace any other statement with `none` when asked for `none`.
    if (fmt !== 'none') {
      throw new PasskeyError('attestation');
    }

    const data = this.parseAuthData(authData, options);
    if (
      !data.credential ||
      !safeEqual(data.credential.id.toString('base64url'), response.id)
    ) {
      throw new PasskeyError('credential');
    }
    if (data.credential.id.length > MAX_CREDENTIAL_ID) {
      throw new PasskeyError('credential');
    }

    let key: ReturnType<typeof coseToSpki>;
    try {
      key = coseToSpki(data.credential.publicKey);
    } catch {
      throw new PasskeyError('key');
    }
    if (await this.storage.passkeys.getPasskey(response.id)) {
      throw new PasskeyError('credential');
    }

    const transports = response.response.transports;
    const record: PasskeyRecord = {
      id: response.id,
      userId,
      publicKey: key.spki.toString('base64url'),
      algorithm: key.algorithm,
      counter: data.counter,
      ...(Array.isArray(transports) && {
        transports: transports.filter((t) => typeof t === 'string'),
      }),
      createdAt: new Date(this.now()),
    };
    await this.storage.passkeys.savePasskey(record);
    return record;
  }

  /**
   * The options for `navigator.credentials.get()`. Without `userId` the
   * browser offers the passkeys it holds for the site (discoverable
   * credentials); with it, only that user's.
   */
  async authenticationOptions({
    userId,
  }: { userId?: string } = {}): Promise<PasskeyAuthenticationOptions> {
    const options = this.feature();
    const challenge = await this.challenge('authentication', userId);
    const allowed =
      userId === undefined
        ? []
        : await this.storage.passkeys.listUserPasskeys(userId);
    return {
      rpId: options.rpId,
      challenge,
      timeout: this.ttl,
      userVerification: this.userVerification,
      allowCredentials: allowed.map(descriptor),
    };
  }

  /**
   * Verifies what `get()` returned. The user to sign in, or `null` for
   * anything wrong with the assertion: one answer for all of them.
   */
  async verifyAuthentication(
    response: PasskeyAuthenticationResponse,
  ): Promise<{ userId: string; credentialId: string } | null> {
    try {
      return await this.assert(response);
    } catch (error) {
      if (error instanceof PasskeyError) {
        return null;
      }
      throw error;
    }
  }

  /** The user's passkeys, oldest first. */
  listPasskeys(userId: string): Promise<PasskeyRecord[]> {
    return this.storage.passkeys.listUserPasskeys(userId);
  }

  /** Removes one of the user's passkeys; `false` if they have none by that id. */
  removePasskey(userId: string, id: string): Promise<boolean> {
    return this.storage.passkeys.deletePasskey(id, userId);
  }

  private async assert(response: PasskeyAuthenticationResponse) {
    const options = this.feature();
    const { challenge, clientData } = await this.takeChallenge(
      response,
      'webauthn.get',
      'authentication',
    );

    const passkey =
      typeof response.id === 'string'
        ? await this.storage.passkeys.getPasskey(response.id)
        : undefined;
    if (
      !passkey ||
      (challenge.userId !== undefined && challenge.userId !== passkey.userId)
    ) {
      throw new PasskeyError('credential');
    }
    const { userHandle } = response.response;
    if (
      userHandle &&
      !safeEqual(
        userHandle,
        Buffer.from(passkey.userId, 'utf8').toString('base64url'),
      )
    ) {
      throw new PasskeyError('user');
    }
    this.checkOrigin(clientData);

    let authData: Buffer;
    let signature: Buffer;
    try {
      authData = decode(response.response.authenticatorData);
      signature = decode(response.response.signature);
    } catch {
      throw new PasskeyError('malformed');
    }
    const data = this.parseAuthData(authData, options);

    const signed = Buffer.concat([
      authData,
      createHash('sha256')
        .update(decode(response.response.clientDataJSON))
        .digest(),
    ]);
    if (
      !verifyAssertion(
        passkey.algorithm,
        Buffer.from(passkey.publicKey, 'base64url'),
        signed,
        signature,
      )
    ) {
      throw new PasskeyError('signature');
    }
    // Both 0: a synced passkey, which has no counter. Otherwise it must advance.
    if (
      (data.counter > 0 || passkey.counter > 0) &&
      data.counter <= passkey.counter
    ) {
      throw new PasskeyError('counter');
    }

    await this.storage.passkeys.touchPasskey(
      passkey.id,
      data.counter,
      new Date(this.now()),
    );
    return { userId: passkey.userId, credentialId: passkey.id };
  }

  /** The options; the module refuses to start with the service used and not configured. */
  private feature(): PasskeyOptions {
    if (!this.options) {
      throw new Error(
        'PasskeyService: passkeys are not enabled. Configure `passkey` in the AuthenticationModule options.',
      );
    }
    return this.options;
  }

  private async challenge(
    type: PasskeyChallengeRecord['type'],
    userId?: string,
  ): Promise<string> {
    const challenge = randomToken();
    const now = this.now();
    await this.storage.passkeys.savePasskeyChallenge({
      id: sha256(challenge),
      type,
      ...(userId !== undefined && { userId }),
      createdAt: new Date(now),
      expiresAt: new Date(now + this.ttl),
    });
    return challenge;
  }

  /** Reads the client data and burns its challenge, whatever else is wrong with the response. */
  private async takeChallenge(
    response: {
      id: string;
      rawId: string;
      type: string;
      response: { clientDataJSON: string };
    },
    type: 'webauthn.create' | 'webauthn.get',
    kind: PasskeyChallengeRecord['type'],
  ) {
    let clientData: ClientData;
    try {
      clientData = JSON.parse(
        decode(response.response.clientDataJSON).toString('utf8'),
      );
      if (
        response.type !== 'public-key' ||
        response.id !== response.rawId ||
        clientData.type !== type
      ) {
        throw new Error('not a ' + type);
      }
      if (
        typeof clientData.challenge !== 'string' ||
        clientData.challenge.length > 128
      ) {
        throw new Error('no challenge');
      }
    } catch {
      throw new PasskeyError('malformed');
    }

    const challenge = await this.storage.passkeys.consumePasskeyChallenge(
      sha256(clientData.challenge),
    );
    if (
      !challenge ||
      challenge.type !== kind ||
      hasExpired(challenge.expiresAt, this.now())
    ) {
      throw new PasskeyError('challenge');
    }
    return { challenge, clientData };
  }

  private checkOrigin(clientData: ClientData) {
    if (
      clientData.crossOrigin === true ||
      !this.feature().origins.includes(clientData.origin as string)
    ) {
      throw new PasskeyError('origin');
    }
  }

  /** Parses authenticator data and checks the relying party and the flags. */
  private parseAuthData(authData: Buffer, options: PasskeyOptions) {
    let data: ReturnType<typeof parseAuthenticatorData>;
    try {
      data = parseAuthenticatorData(authData);
    } catch {
      throw new PasskeyError('malformed');
    }
    if (
      !data.rpIdHash.equals(createHash('sha256').update(options.rpId).digest())
    ) {
      throw new PasskeyError('rp-id');
    }
    // A backed-up credential must be backup eligible.
    if (
      !(data.flags & FLAG_UP) ||
      (data.flags & FLAG_BS && !(data.flags & FLAG_BE))
    ) {
      throw new PasskeyError('flags');
    }
    if (this.userVerification === 'required' && !(data.flags & FLAG_UV)) {
      throw new PasskeyError('flags');
    }
    return data;
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}

interface ClientData {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
}

function descriptor(passkey: PasskeyRecord): PasskeyDescriptor {
  return {
    type: 'public-key',
    id: passkey.id,
    ...(passkey.transports && { transports: passkey.transports }),
  };
}

/** base64url → bytes; anything else (non-strings included) throws. */
function decode(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new TypeError('not base64url');
  }
  return Buffer.from(value, 'base64url');
}
