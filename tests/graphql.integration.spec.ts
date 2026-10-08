/**
 * The browser flows over GraphQL (Apollo on Express), with a context that carries `req` and
 * `res`: `SignInService` sets and clears the session cookie on the HTTP response of a
 * mutation, a pending second factor and an unverified address are refused with GraphQL
 * errors a client can tell apart, the package's errors thrown by resolvers keep their
 * status, and the session cookie is ignored on cross-origin operations.
 */
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import { Injectable, Module, type INestApplication } from '@nestjs/common';
import { Args, GraphQLModule, Mutation, Query, Resolver } from '@nestjs/graphql';
import request from 'supertest';
import { createApp } from './support/adapters.js';
import {
  Authenticate,
  AuthenticationContext,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  MfaService,
  Public,
  SessionCookieProvider,
  SignInService,
  type SessionRecord,
} from '../lib/index.js';
import { base32Decode, hotp } from '../lib/mfa/otp.util.js';

const typeDefs = /* GraphQL */ `
  type Enrollment {
    secret: String!
  }
  type Query {
    me: String
    orders: [String!]
    mine: String
  }
  type Mutation {
    signIn(userId: String!): String
    completeMfa(code: String!): Boolean
    signOut: Boolean
    enroll: Enrollment
    confirm(code: String!): Boolean
  }
`;

const verified = new Set(['verified-user']);
const totp = (secret: string, offset = 0) => hotp(base32Decode(secret), Math.floor(Date.now() / 30_000) + offset);

@Injectable()
class SessionAuth extends SessionCookieProvider<{ id: string; emailVerified: boolean }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return { id: session.userId, emailVerified: verified.has(session.userId) };
  }
}

@Resolver()
class AccountResolver {
  constructor(
    private readonly signInService: SignInService,
    private readonly mfaService: MfaService,
    private readonly authenticationContext: AuthenticationContext,
  ) {}

  @Public()
  @Mutation('signIn')
  async signIn(@Args('userId') userId: string) {
    const { session } = await this.signInService.signIn(userId, { method: 'password' });
    return session.mfa ?? 'none';
  }

  @Public()
  @Mutation('completeMfa')
  async completeMfa(@Args('code') code: string) {
    return !!(await this.signInService.completeMfa({ code }));
  }

  @Public()
  @Mutation('signOut')
  signOut() {
    return this.signInService.signOut();
  }

  @Mutation('enroll')
  enroll(@CurrentUser('id') id: string) {
    return this.mfaService.enroll(id, `${id}@example.com`);
  }

  @Mutation('confirm')
  confirm(@CurrentUser('id') id: string, @Args('code') code: string) {
    return this.signInService.confirmMfa(id, code);
  }

  @Query('me')
  me(@CurrentUser('id') id: string) {
    return id;
  }

  @Authenticate({ verifiedEmail: true })
  @Query('orders')
  orders() {
    return ['order-1'];
  }

  @Public()
  @Query('mine')
  mine() {
    return this.authenticationContext.requireUser().id;
  }
}

@Module({
  imports: [
    AuthenticationModule.forRoot({ mfa: { encryption: false } }),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      typeDefs,
      context: ({ req, res }: { req: unknown; res: unknown }) => ({ req, res }),
    }),
  ],
  providers: [SessionAuth, AccountResolver],
})
class GqlAppModule {}

const sessionCookie = (res: request.Response) =>
  ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith('__Host-sid='));

describe('browser flows over GraphQL (Apollo, express)', () => {
  let app: INestApplication;
  const gql = (query: string, { cookie, origin }: { cookie?: string; origin?: string } = {}) => {
    const req = request(app.getHttpServer()).post('/graphql');
    if (cookie) {
      req.set('Cookie', cookie);
    }
    if (origin) {
      req.set('Origin', origin);
    }
    return req.send({ query }).expect(200);
  };
  const signIn = async (userId: string) => {
    const res = await gql(`mutation { signIn(userId: "${userId}") }`);
    return { mfa: res.body.data.signIn as string, cookie: sessionCookie(res)!.split(';')[0] };
  };

  beforeAll(async () => {
    app = await createApp('express', GqlAppModule);
  });
  afterAll(() => app.close());

  it('sets the session cookie on the mutation’s HTTP response, reads it on later operations, and clears it on sign-out', async () => {
    const res = await gql('mutation { signIn(userId: "ada") }');
    expect(res.body.data.signIn).toBe('none');
    expect(sessionCookie(res)).toMatch(/^__Host-sid=[\w-]{43}; .*HttpOnly/);
    const cookie = sessionCookie(res)!.split(';')[0];

    expect((await gql('{ me }', { cookie })).body.data.me).toBe('ada');

    const signedOut = await gql('mutation { signOut }', { cookie });
    expect(signedOut.body.data.signOut).toBe(true);
    expect(sessionCookie(signedOut)).toMatch(/^__Host-sid=;.*Max-Age=0/);
    expect((await gql('{ me }', { cookie })).body.errors[0].extensions.code).toBe('UNAUTHENTICATED');
    expect((await gql('mutation { signOut }')).body.data.signOut).toBe(false);
  });

  it('refuses an unverified address with FORBIDDEN, and a verified one passes', async () => {
    const unverified = await signIn('ada');
    const refused = await gql('{ orders }', unverified);
    expect(refused.body.errors[0]).toMatchObject({
      message: 'Email address not verified',
      extensions: { code: 'FORBIDDEN', originalError: { error: 'email_unverified', errorCode: 'email_unverified', statusCode: 403 } },
    });

    const ok = await signIn('verified-user');
    expect((await gql('{ orders }', ok)).body.data.orders).toEqual(['order-1']);
  });

  it('turns requireUser() in a public resolver into UNAUTHENTICATED, and a second enrollment into a 409', async () => {
    const anonymous = await gql('{ mine }');
    expect(anonymous.body.errors[0]).toMatchObject({ message: 'Unauthorized', extensions: { code: 'UNAUTHENTICATED' } });

    const grace = await signIn('grace');
    const { secret } = (await gql('mutation { enroll { secret } }', grace)).body.data.enroll;
    const confirmed = await gql(`mutation { confirm(code: "${totp(secret, -1)}") }`, grace);
    expect(confirmed.body.data.confirm).toBe(true);

    const verifiedCookie = sessionCookie(confirmed)!.split(';')[0];
    const again = await gql('mutation { enroll { secret } }', { cookie: verifiedCookie });
    // Apollo has no code for a 409: Nest's driver keeps the status and the exception's body.
    expect(again.body.errors[0]).toMatchObject({
      message: 'Authenticator already enrolled',
      extensions: { status: 409, originalError: { message: 'Authenticator already enrolled', error: 'Conflict', statusCode: 409 } },
    });
  });

  it('keeps a pending sign-in anonymous until completeMfa, which sets the verified cookie', async () => {
    const userId = 'mfa-user';
    const first = await signIn(userId);
    const { secret } = (await gql('mutation { enroll { secret } }', first)).body.data.enroll;
    await gql(`mutation { confirm(code: "${totp(secret, -1)}") }`, first);

    const pending = await signIn(userId);
    expect(pending.mfa).toBe('pending');
    const refused = await gql('{ me }', pending);
    expect(refused.body.errors[0]).toMatchObject({
      message: 'Second factor required',
      extensions: { code: 'UNAUTHENTICATED', originalError: { error: 'mfa_required', errorCode: 'mfa_required', statusCode: 401 } },
    });

    const completed = await gql(`mutation { completeMfa(code: "${totp(secret)}") }`, pending);
    expect(completed.body.data.completeMfa).toBe(true);
    const cookie = sessionCookie(completed)!.split(';')[0];
    expect((await gql('{ me }', { cookie })).body.data.me).toBe(userId);
  });

  it('ignores the session cookie on operations from another origin, and refuses to sign in from there', async () => {
    const { cookie } = await signIn('ada');

    const hijacked = await gql('{ me }', { cookie, origin: 'https://evil.test' });
    expect(hijacked.body.errors[0].extensions.code).toBe('UNAUTHENTICATED');

    const loginCsrf = await gql('mutation { signIn(userId: "attacker") }', { origin: 'https://evil.test' });
    expect(loginCsrf.body.errors[0].extensions.code).toBe('FORBIDDEN');
    expect(sessionCookie(loginCsrf)).toBeUndefined();
  });
});
