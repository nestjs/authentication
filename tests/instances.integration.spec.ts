/**
 * What an operator sees across instances and deploys. Two instances (one on Express, one on
 * Fastify) whose provider registers the same stores: a session or a refresh-token family
 * started on one is honoured, ended and caught reused on the other. Then a TOTP key rotation
 * over successive deploys on the same MFA store: the previous key still decrypts, the first
 * verification re-encrypts under the new key, and a deploy without any key that decrypts a
 * secret fails closed, logging it, without counting it against the user.
 */
import { Body, Controller, Get, HttpCode, Injectable, Logger, Module, Post, UnauthorizedException, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createApp } from './support/adapters.js';
import {
  AuthenticationModule,
  AuthenticationRegistry,
  AuthenticationStorage,
  CurrentUser,
  InMemoryMfaStore,
  InMemoryRefreshTokenStore,
  InMemorySessionStore,
  MfaService,
  Public,
  SessionCookieProvider,
  SignInService,
  TokenService,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';

const KEYS = {
  first: 'first-totp-encryption-key-of-32-characters',
  second: 'second-totp-encryption-key-of-32-characters',
  unrelated: 'unrelated-totp-encryption-key-32-characters',
};

/** What a database would hold, shared by every instance and every deploy. */
const database = {
  sessions: new InMemorySessionStore(),
  refreshTokens: new InMemoryRefreshTokenStore(),
  mfa: new InMemoryMfaStore(),
};

// The app's TOTP clock (`mfa.now`), fixed when the file loads: on the wall clock the 30-second step
// can turn between making a code and the app checking it, and the previous step's code is then refused.
const clock = Date.now();
const totp = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(clock / 30_000) + offset);
const cookieOf = (res: request.Response) =>
  ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith('__Host-sid='))?.split(';')[0];

@Injectable()
class DatabaseStore {
  constructor(storage: AuthenticationStorage) {
    storage.registerSource(database);
  }
}

@Injectable()
class SessionAuth extends SessionCookieProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return { id: session.userId };
  }
}

@Controller()
class AppController {
  constructor(
    private readonly signInService: SignInService,
    private readonly tokenService: TokenService,
    private readonly mfaService: MfaService,
  ) {}

  @Public()
  @Post('sign-in')
  @HttpCode(200)
  async signIn(@Body('userId') userId: string) {
    const { session } = await this.signInService.signIn(userId, { method: 'password' });
    return { mfa: session.mfa ?? null };
  }

  @Public()
  @Post('mfa')
  @HttpCode(200)
  async completeMfa(@Body('code') code: string) {
    if (!(await this.signInService.completeMfa({ code }))) {
      throw new UnauthorizedException();
    }
  }

  @Post('mfa/enroll')
  enroll(@CurrentUser('id') id: string) {
    return this.mfaService.enroll(id, `${id}@example.com`);
  }

  @Post('mfa/confirm')
  @HttpCode(200)
  async confirm(@CurrentUser('id') id: string, @Body('code') code: string) {
    if (!(await this.signInService.confirmMfa(id, code))) {
      throw new UnauthorizedException();
    }
  }

  @Public()
  @Post('sign-out')
  @HttpCode(204)
  async signOut() {
    await this.signInService.signOut();
  }

  @Public()
  @Post('token')
  @HttpCode(200)
  token(@Body('userId') userId: string) {
    return this.tokenService.issue(userId);
  }

  @Public()
  @Post('token/refresh')
  @HttpCode(200)
  refresh(@Body('refreshToken') refreshToken: string) {
    return this.tokenService.refresh(refreshToken);
  }

  @Get('me')
  me(@CurrentUser('id') id: string) {
    return { id };
  }
}

function deploy(keys: string[]) {
  @Module({
    imports: [
      AuthenticationModule.forRoot({
        accessToken: { key: 'instances-test-secret-of-at-least-32-bytes' },
        mfa: { encryption: { keys }, now: () => clock },
      }),
    ],
    controllers: [AppController],
    providers: [DatabaseStore, SessionAuth],
  })
  class InstanceModule {}
  return InstanceModule;
}

describe('two instances on one set of stores (Express and Fastify)', () => {
  let a: INestApplication;
  let b: INestApplication;

  beforeAll(async () => {
    a = await createApp('express', deploy([KEYS.first]));
    b = await createApp('fastify', deploy([KEYS.first]));
  });
  afterAll(async () => {
    await a.close();
    await b.close();
  });

  it('honours on one instance the session the other started, and ends it everywhere', async () => {
    const cookie = cookieOf(await request(a.getHttpServer()).post('/sign-in').send({ userId: 'ada' }).expect(200))!;

    await request(b.getHttpServer()).get('/me').set('Cookie', cookie).expect(200, { id: 'ada' });
    await request(b.getHttpServer()).post('/sign-out').set('Cookie', cookie).expect(204);
    await request(a.getHttpServer()).get('/me').set('Cookie', cookie).expect(401);
  });

  it('catches a refresh token reused on another instance, and ends the family on both', async () => {
    const issued = (await request(a.getHttpServer()).post('/token').send({ userId: 'grace' }).expect(200)).body;
    const rotated = (await request(b.getHttpServer()).post('/token/refresh').send({ refreshToken: issued.refreshToken }).expect(200)).body;

    await request(a.getHttpServer()).post('/token/refresh').send({ refreshToken: issued.refreshToken }).expect(401);
    await request(b.getHttpServer()).post('/token/refresh').send({ refreshToken: rotated.refreshToken }).expect(401);
  });

  it('asks for the second factor on one instance for an authenticator enrolled on the other', async () => {
    const cookie = cookieOf(await request(a.getHttpServer()).post('/sign-in').send({ userId: 'linus' }).expect(200))!;
    const { secret } = (await request(a.getHttpServer()).post('/mfa/enroll').set('Cookie', cookie).expect(201)).body;
    await request(a.getHttpServer()).post('/mfa/confirm').set('Cookie', cookie).send({ code: totp(secret, -1) }).expect(200);

    await request(b.getHttpServer()).post('/sign-in').send({ userId: 'linus' }).expect(200, { mfa: 'pending' });
  });
});

describe('rotating the TOTP encryption key over deploys', () => {
  const userId = 'rotating-user';
  const keyIdOf = async () => (await database.mfa.getTotp(userId))!.secret.split('.')[1];

  /** Boots a deploy with these keys, runs `run` against it, and shuts it down. */
  async function onDeploy(keys: string[], run: (app: INestApplication) => Promise<void>) {
    const app = await createApp('express', deploy(keys));
    try {
      await run(app);
    } finally {
      await app.close();
    }
  }
  const signInWithCode = async (app: INestApplication, code: string) => {
    const pending = cookieOf(await request(app.getHttpServer()).post('/sign-in').send({ userId }).expect(200, { mfa: 'pending' }))!;
    return request(app.getHttpServer()).post('/mfa').set('Cookie', pending).send({ code });
  };

  it('keeps authenticators working, re-encrypted under the new key at their next use, and fails closed without a key', async () => {
    let secret = '';
    let firstKeyId = '';
    await onDeploy([KEYS.first], async (app) => {
      const cookie = cookieOf(await request(app.getHttpServer()).post('/sign-in').send({ userId }).expect(200))!;
      secret = (await request(app.getHttpServer()).post('/mfa/enroll').set('Cookie', cookie).expect(201)).body.secret;
      await request(app.getHttpServer()).post('/mfa/confirm').set('Cookie', cookie).send({ code: totp(secret, -1) }).expect(200);
      firstKeyId = await keyIdOf();
    });

    await onDeploy([KEYS.second, KEYS.first], async (app) => {
      expect(await keyIdOf()).toBe(firstKeyId);
      expect((await signInWithCode(app, totp(secret))).status).toBe(200);
    });
    const secondKeyId = await keyIdOf();
    expect(secondKeyId).not.toBe(firstKeyId);

    await onDeploy([KEYS.second], async (app) => {
      expect((await signInWithCode(app, totp(secret, 1))).status).toBe(200);
    });
    expect(await keyIdOf()).toBe(secondKeyId);

    // A deploy with no key that decrypts the secret fails closed, logs it, and counts nothing.
    const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});

    await onDeploy([KEYS.unrelated], async (app) => {
      expect((await signInWithCode(app, totp(secret))).status).toBe(401);
    });

    expect(logged).toHaveBeenCalledWith(expect.stringMatching(/^TOTP secret of user rotating-user could not be decrypted: /));
    expect(await database.mfa.countMfaFailures(userId, 15 * 60_000, Date.now())).toBe(0);
    logged.mockRestore();
  });
});
