/** `PasskeyService` against a software authenticator that builds the bytes a browser would send. */
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  InMemoryPasskeyStore,
  PasskeyError,
  PasskeyService,
  type PasskeyAuthenticationResponse,
  type PasskeyOptions,
  type PasskeyRegistrationResponse,
} from '../lib/index.js';
import { storageWith } from './fixtures.js';

const ORIGIN = 'https://app.test';
const RP_ID = 'app.test';
const sha = (data: Buffer | string) =>
  createHash('sha256').update(data).digest();

// A CBOR encoder for what a COSE key and an attestation object hold.
function cbor(value: unknown): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  };
  if (typeof value === 'number')
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string')
    return Buffer.concat([
      head(3, Buffer.byteLength(value)),
      Buffer.from(value),
    ]);
  if (Buffer.isBuffer(value))
    return Buffer.concat([head(2, value.length), value]);
  const entries = [...(value as Map<unknown, unknown>)];
  return Buffer.concat([
    head(5, entries.length),
    ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)]),
  ]);
}

type Kind = 'ES256' | 'RS256' | 'EdDSA';

class Authenticator {
  readonly id = randomBytes(32);
  counter = 0;
  private readonly privateKey: KeyObject;
  private readonly cose: Buffer;

  constructor(readonly kind: Kind) {
    if (kind === 'ES256') {
      const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });
      const jwk = publicKey.export({ format: 'jwk' });
      this.privateKey = privateKey;
      this.cose = cbor(
        new Map<unknown, unknown>([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, Buffer.from(jwk.x!, 'base64url')],
          [-3, Buffer.from(jwk.y!, 'base64url')],
        ]),
      );
    } else if (kind === 'RS256') {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const jwk = publicKey.export({ format: 'jwk' });
      this.privateKey = privateKey;
      this.cose = cbor(
        new Map<unknown, unknown>([
          [1, 3],
          [3, -257],
          [-1, Buffer.from(jwk.n!, 'base64url')],
          [-2, Buffer.from(jwk.e!, 'base64url')],
        ]),
      );
    } else {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const jwk = publicKey.export({ format: 'jwk' });
      this.privateKey = privateKey;
      this.cose = cbor(
        new Map<unknown, unknown>([
          [1, 1],
          [3, -8],
          [-1, 6],
          [-2, Buffer.from(jwk.x!, 'base64url')],
        ]),
      );
    }
  }

  private authData(flags: number, { rpId = RP_ID, attested = false } = {}) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const base = Buffer.concat([
      sha(rpId),
      Buffer.from([flags | (attested ? 0x40 : 0)]),
      counter,
    ]);
    if (!attested) return base;
    const length = Buffer.alloc(2);
    length.writeUInt16BE(this.id.length);
    return Buffer.concat([base, Buffer.alloc(16), length, this.id, this.cose]);
  }

  register(
    challenge: string,
    { origin = ORIGIN, flags = 0x05, rpId = RP_ID, fmt = 'none' } = {},
  ): PasskeyRegistrationResponse {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.create', challenge, origin }),
    );
    const attestationObject = cbor(
      new Map<unknown, unknown>([
        ['fmt', fmt],
        ['attStmt', new Map()],
        ['authData', this.authData(flags, { rpId, attested: true })],
      ]),
    );
    return {
      id: this.id.toString('base64url'),
      rawId: this.id.toString('base64url'),
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        attestationObject: attestationObject.toString('base64url'),
        transports: ['internal'],
      },
    };
  }

  assert(
    challenge: string,
    userHandle: string | null,
    {
      origin = ORIGIN,
      flags = 0x05,
      rpId = RP_ID,
      counter,
    }: {
      origin?: string;
      flags?: number;
      rpId?: string;
      counter?: number;
    } = {},
  ): PasskeyAuthenticationResponse {
    this.counter = counter ?? this.counter;
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge, origin }),
    );
    const authenticatorData = this.authData(flags, { rpId });
    const signature = sign(
      this.kind === 'EdDSA' ? null : 'sha256',
      Buffer.concat([authenticatorData, sha(clientDataJSON)]),
      this.privateKey,
    );
    return {
      id: this.id.toString('base64url'),
      rawId: this.id.toString('base64url'),
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        authenticatorData: authenticatorData.toString('base64url'),
        signature: signature.toString('base64url'),
        userHandle,
      },
    };
  }
}

function setup(passkey: Partial<PasskeyOptions> = {}) {
  let clock = 1_700_000_000_000;
  const store = new InMemoryPasskeyStore();
  const service = new PasskeyService(storageWith({ passkeys: store }), {
    passkey: {
      rpId: RP_ID,
      rpName: 'App',
      origins: [ORIGIN],
      now: () => clock,
      ...passkey,
    },
  });
  const user = { id: 'user-1', name: 'ada@example.com' };
  const handle = Buffer.from(user.id).toString('base64url');

  const enroll = async (authenticator: Authenticator) => {
    const options = await service.registrationOptions(user);
    return service.verifyRegistration(
      user.id,
      authenticator.register(options.challenge),
    );
  };
  return {
    service,
    store,
    user,
    handle,
    enroll,
    advance: (ms: number) => (clock += ms),
  };
}

const reason = (promise: Promise<unknown>) =>
  promise.then(
    () => undefined,
    (error: PasskeyError) => error.reason,
  );

describe('PasskeyService', () => {
  for (const kind of ['ES256', 'RS256', 'EdDSA'] as const) {
    it(`registers and signs in with a ${kind} passkey, with discoverable credentials`, async () => {
      const { service, handle, enroll, user } = setup();
      const authenticator = new Authenticator(kind);
      const record = await enroll(authenticator);
      expect(record).toMatchObject({
        userId: user.id,
        algorithm: kind,
        counter: 0,
        transports: ['internal'],
      });

      const options = await service.authenticationOptions();
      expect(options).toMatchObject({ rpId: RP_ID, allowCredentials: [] });
      expect(
        await service.verifyAuthentication(
          authenticator.assert(options.challenge, handle),
        ),
      ).toEqual({
        userId: user.id,
        credentialId: record.id,
      });
    });
  }

  it('describes the registration: no attestation, existing passkeys excluded', async () => {
    const { service, user, enroll } = setup();
    const first = await service.registrationOptions(user);
    expect(first).toMatchObject({
      rp: { id: RP_ID, name: 'App' },
      user: { id: Buffer.from(user.id).toString('base64url') },
      attestation: 'none',
      excludeCredentials: [],
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
        { type: 'public-key', alg: -8 },
      ],
    });
    const authenticator = new Authenticator('ES256');
    await enroll(authenticator);
    expect(
      (await service.registrationOptions(user)).excludeCredentials,
    ).toEqual([
      {
        type: 'public-key',
        id: authenticator.id.toString('base64url'),
        transports: ['internal'],
      },
    ]);
  });

  it('refuses a registration with a wrong origin, rp id, flags, attestation, user or a reused challenge', async () => {
    const { service, user } = setup();
    const authenticator = new Authenticator('ES256');
    const attempt = async (
      response: (challenge: string) => PasskeyRegistrationResponse,
      userId = user.id,
    ) => {
      const { challenge } = await service.registrationOptions(user);
      return reason(service.verifyRegistration(userId, response(challenge)));
    };

    expect(
      await attempt((c) =>
        authenticator.register(c, { origin: 'https://evil.test' }),
      ),
    ).toBe('origin');
    expect(
      await attempt((c) => authenticator.register(c, { rpId: 'evil.test' })),
    ).toBe('rp-id');
    expect(
      await attempt((c) => authenticator.register(c, { flags: 0x04 })),
    ).toBe('flags');
    expect(
      await attempt((c) => authenticator.register(c, { flags: 0x10 | 0x01 })),
    ).toBe('flags'); // backed up, not eligible
    expect(
      await attempt((c) => authenticator.register(c, { fmt: 'packed' })),
    ).toBe('attestation');
    expect(
      await attempt((c) => authenticator.register(c), 'someone-else'),
    ).toBe('user');

    const { challenge } = await service.registrationOptions(user);
    await service.verifyRegistration(
      user.id,
      authenticator.register(challenge),
    );
    expect(
      await reason(
        service.verifyRegistration(user.id, authenticator.register(challenge)),
      ),
    ).toBe('challenge');
    expect(await attempt((c) => authenticator.register(c))).toBe('credential'); // already registered
    expect(await service.listPasskeys(user.id)).toHaveLength(1);
  });

  it('refuses a registration challenge as an authentication one, and the reverse', async () => {
    const { service, user, handle, enroll } = setup();
    const authenticator = new Authenticator('ES256');
    await enroll(authenticator);

    const registration = await service.registrationOptions(user);
    expect(
      await service.verifyAuthentication(
        authenticator.assert(registration.challenge, handle),
      ),
    ).toBeNull();
    const authentication = await service.authenticationOptions();
    expect(
      await reason(
        service.verifyRegistration(
          user.id,
          authenticator.register(authentication.challenge),
        ),
      ),
    ).toBe('challenge');
  });

  it('answers null for every failed assertion, and burns the challenge each time', async () => {
    const { service, handle, enroll, advance } = setup();
    const authenticator = new Authenticator('ES256');
    await enroll(authenticator);
    const other = new Authenticator('ES256');
    const challenge = async () =>
      (await service.authenticationOptions()).challenge;

    expect(
      await service.verifyAuthentication(
        authenticator.assert(await challenge(), handle, {
          origin: 'https://evil.test',
        }),
      ),
    ).toBeNull();
    expect(
      await service.verifyAuthentication(
        authenticator.assert(await challenge(), handle, { rpId: 'evil.test' }),
      ),
    ).toBeNull();
    expect(
      await service.verifyAuthentication(
        authenticator.assert(await challenge(), handle, { flags: 0x04 }),
      ),
    ).toBeNull(); // no presence
    expect(
      await service.verifyAuthentication(
        authenticator.assert(
          await challenge(),
          Buffer.from('user-2').toString('base64url'),
        ),
      ),
    ).toBeNull();
    expect(
      await service.verifyAuthentication(
        other.assert(await challenge(), handle),
      ),
    ).toBeNull(); // unknown credential

    const forged = authenticator.assert(await challenge(), handle);
    forged.response.signature = Buffer.alloc(70, 1).toString('base64url');
    expect(await service.verifyAuthentication(forged)).toBeNull();

    const expired = await challenge();
    advance(6 * 60_000);
    expect(
      await service.verifyAuthentication(authenticator.assert(expired, handle)),
    ).toBeNull();
    expect(await service.verifyAuthentication({} as never)).toBeNull();
  });

  it('takes a challenge once: parallel assertions of one challenge sign in one', async () => {
    const { service, handle, enroll } = setup();
    const authenticator = new Authenticator('ES256');
    await enroll(authenticator);
    const { challenge } = await service.authenticationOptions();
    const response = authenticator.assert(challenge, handle);

    const results = await Promise.all(
      Array.from({ length: 5 }, () => service.verifyAuthentication(response)),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('accepts a counter that stays 0 (synced passkeys), and refuses one that does not advance once it has', async () => {
    const { service, store, handle, enroll } = setup();
    const synced = new Authenticator('ES256');
    const record = await enroll(synced);
    for (let i = 0; i < 3; i++) {
      expect(
        await service.verifyAuthentication(
          synced.assert(
            (await service.authenticationOptions()).challenge,
            handle,
          ),
        ),
      ).not.toBeNull();
    }
    expect((await store.getPasskey(record.id))?.counter).toBe(0);

    for (const counter of [5, 6]) {
      expect(
        await service.verifyAuthentication(
          synced.assert(
            (await service.authenticationOptions()).challenge,
            handle,
            { counter },
          ),
        ),
      ).not.toBeNull();
    }
    expect((await store.getPasskey(record.id))?.counter).toBe(6);
    for (const counter of [6, 3, 0]) {
      expect(
        await service.verifyAuthentication(
          synced.assert(
            (await service.authenticationOptions()).challenge,
            handle,
            { counter },
          ),
        ),
      ).toBeNull();
    }
    expect((await store.getPasskey(record.id))?.counter).toBe(6);
  });

  it('requires user verification when configured', async () => {
    const { service, handle, enroll } = setup({ userVerification: 'required' });
    const authenticator = new Authenticator('ES256');
    const options = await service.registrationOptions({
      id: 'user-1',
      name: 'ada',
    });
    expect(
      await reason(
        service.verifyRegistration(
          'user-1',
          authenticator.register(options.challenge, { flags: 0x01 }),
        ),
      ),
    ).toBe('flags');
    await enroll(authenticator);
    expect(
      await service.verifyAuthentication(
        authenticator.assert(
          (await service.authenticationOptions()).challenge,
          handle,
          { flags: 0x01 },
        ),
      ),
    ).toBeNull();
    expect(
      await service.verifyAuthentication(
        authenticator.assert(
          (await service.authenticationOptions()).challenge,
          handle,
        ),
      ),
    ).not.toBeNull();
  });

  it('restricts an authentication to the user it was asked for', async () => {
    const { service, handle, enroll } = setup();
    const authenticator = new Authenticator('ES256');
    const record = await enroll(authenticator);

    const mine = await service.authenticationOptions({ userId: 'user-1' });
    expect(mine.allowCredentials.map((c) => c.id)).toEqual([record.id]);
    expect(
      await service.verifyAuthentication(
        authenticator.assert(mine.challenge, handle),
      ),
    ).not.toBeNull();

    const theirs = await service.authenticationOptions({ userId: 'user-2' });
    expect(theirs.allowCredentials).toEqual([]);
    expect(
      await service.verifyAuthentication(
        authenticator.assert(theirs.challenge, handle),
      ),
    ).toBeNull();
  });

  it('lists and removes the user’s own passkeys', async () => {
    const { service, user, enroll } = setup();
    const record = await enroll(new Authenticator('EdDSA'));
    expect(await service.listPasskeys(user.id)).toEqual([record]);
    expect(await service.removePasskey('user-2', record.id)).toBe(false);
    expect(await service.removePasskey(user.id, record.id)).toBe(true);
    expect(await service.listPasskeys(user.id)).toEqual([]);
  });

  it('fails without options, and on options that cannot work', async () => {
    const storage = storageWith({ passkeys: new InMemoryPasskeyStore() });
    await expect(
      new PasskeyService(storage).authenticationOptions(),
    ).rejects.toThrow('passkeys are not enabled');
    expect(
      () =>
        new PasskeyService(storage, {
          passkey: { rpId: RP_ID, rpName: 'App', origins: [] },
        }),
    ).toThrow('non-empty `origins`');
    await expect(
      setup().service.registrationOptions({ id: 'x'.repeat(65), name: 'n' }),
    ).rejects.toThrow('1 to 64 bytes');
  });
});
