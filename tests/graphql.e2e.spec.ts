import { setTimeout as sleep } from 'node:timers/promises';
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import { Module, type INestApplication } from '@nestjs/common';
import { GraphQLModule, Query, ResolveField, Resolver } from '@nestjs/graphql';
import request from 'supertest';
import { createApp } from './support/adapters.js';
import { AuthenticationContext, CurrentUser, Public } from '../lib/index.js';
import { ApiKeyRepository, ApiKeysModule, AuthProvidersModule, authenticationModule, UsersModule, type User } from './fixtures.js';

const typeDefs = /* GraphQL */ `
  type Viewer {
    id: ID!
    contextId: ID
  }
  type Query {
    viewer: Viewer
    hello: String
  }
`;

@Resolver('Viewer')
class ViewerResolver {
  constructor(private readonly auth: AuthenticationContext) {}

  @Query('viewer')
  async viewer(@CurrentUser() user: User) {
    await sleep(Math.random() * 10);
    return { id: user.id };
  }

  @Query('hello')
  @Public()
  hello() {
    return `hello ${this.auth.user?.id ?? 'guest'}`;
  }

  // Field resolvers only get enhancers with `fieldResolverEnhancers`; the
  // guard then reuses the per-request result instead of authenticating again.
  @ResolveField('contextId')
  async contextId() {
    await sleep(Math.random() * 10);
    return this.auth.user?.id ?? null;
  }
}

@Module({
  imports: [
    authenticationModule(),
    UsersModule,
    AuthProvidersModule,
    ApiKeysModule,
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      typeDefs,
      context: ({ req }: { req: unknown }) => ({ req }),
      fieldResolverEnhancers: ['guards', 'interceptors'],
    }),
  ],
  providers: [ViewerResolver],
})
class GqlAppModule {}

describe('a GraphQL context object', () => {
  it('fails at startup: one object for every request would authenticate each as the first caller', async () => {
    @Module({
      imports: [
        authenticationModule(),
        UsersModule,
        AuthProvidersModule,
        ApiKeysModule,
        GraphQLModule.forRoot<ApolloDriverConfig>({ driver: ApolloDriver, typeDefs, context: { tenant: 'static' } }),
      ],
      providers: [ViewerResolver],
    })
    class StaticContextModule {}

    await expect(createApp('express', StaticContextModule)).rejects.toThrow(
      /^AuthenticationModule: the GraphQL module’s `context` is an object, shared by every request/,
    );
  });
});

describe('GraphQL (Apollo, express)', () => {
  let app: INestApplication;
  const gql = (query: string, key?: string) => {
    const req = request(app.getHttpServer()).post('/graphql');
    if (key) {
      req.set('x-api-key', key);
    }
    return req.send({ query });
  };

  beforeAll(async () => {
    app = await createApp('express', GqlAppModule);
  });
  afterAll(() => app.close());

  it('authenticates resolvers from context.req; @CurrentUser and AuthenticationContext work, field resolvers included', async () => {
    const lookups = vi.spyOn(app.get(ApiKeyRepository), 'find');
    const res = await gql('{ viewer { id contextId } }', 'key-ci').expect(200);
    expect(res.body.data.viewer).toEqual({ id: 'svc-ci', contextId: 'svc-ci' });
    expect(lookups).toHaveBeenCalledTimes(1); // the field resolver's guard reused the result
    lookups.mockRestore();
  });

  it('rejects anonymous operations with UNAUTHENTICATED and leaves @Public resolvers open', async () => {
    const res = await gql('{ viewer { id } }').expect(200);
    expect(res.body.errors[0]).toMatchObject({ message: 'Unauthorized', extensions: { code: 'UNAUTHENTICATED' } });
    expect(res.body.errors[0].extensions.originalError).toEqual({ message: 'Unauthorized', statusCode: 401, errorCode: 'missing_credentials' });
    expect((await gql('{ hello }').expect(200)).body.data.hello).toBe('hello guest');
  });

  it('a @Public root field does not clear the user for the other fields of the same operation', async () => {
    const res = await gql('{ hello viewer { id } }', 'key-ci').expect(200);
    expect(res.body.data.viewer).toEqual({ id: 'svc-ci' });
    expect(res.body.errors).toBeUndefined();
  });

  it('keeps concurrent operations apart', async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => gql('{ viewer { contextId } }', i % 2 ? 'key-ci' : undefined)),
    );

    results.forEach((res, i) => {
      if (i % 2) {
        expect(res.body.data.viewer.contextId).toBe('svc-ci');
      } else {
        expect(res.body.errors[0].message).toBe('Unauthorized');
      }
    });
  });
});
