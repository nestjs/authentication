/**
 * The real `@nestjs/authentication` in front of `@Can()` and `authorize()` on the other
 * transports: GraphQL (Apollo), WebSockets (platform-ws) and a TCP microservice. With nothing
 * to configure, authorization's default lookup reads the user authentication left in each
 * transport's place, and each denial reaches the client in that transport's shape.
 */
import type { IncomingMessage } from 'node:http';
import type { AddressInfo, Server as NetServer } from 'node:net';
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import { Controller, Injectable, Module, type ExecutionContext, type INestApplication, type INestMicroservice } from '@nestjs/common';
import { Args, GraphQLModule, Mutation, Query, Resolver } from '@nestjs/graphql';
import { ClientProxyFactory, MessagePattern, Payload, Transport, type ClientProxy } from '@nestjs/microservices';
import { WsAdapter } from '@nestjs/platform-ws';
import { MessageBody, SubscribeMessage, WebSocketGateway, type OnGatewayConnection } from '@nestjs/websockets';
import { Test } from '@nestjs/testing';
import { lastValueFrom } from 'rxjs';
import request from 'supertest';
import { WebSocket } from 'ws';
import { createApp } from './support/adapters.js';
import {
  Authenticate,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentUser,
  PasswordHasher,
  TokenService,
  WsAuthenticator,
  type AuthenticationResult,
} from '../lib/index.js';
import { AuthorizationEvents, AuthorizationModule, Can, type AuthorizationDeniedEvent } from '@nestjs/authorization';
import {
  ada,
  alice,
  alicePaid,
  AuthModule,
  authenticationModule,
  ProductPolicy,
  ProductsService,
  bobPaid,
  cheapHasher,
  OrderPolicy,
  OrdersService,
  RefundLimitsService,
  sam,
  type Product,
  type User,
} from './fixtures/authorization-tutorial.js';

const withCheapHasher = { override: (builder: any) => builder.overrideProvider(PasswordHasher).useValue(cheapHasher()) };

describe('GraphQL (Apollo) with @nestjs/authentication', () => {
  @Resolver('Product')
  class ProductsResolver {
    constructor(private readonly productsService: ProductsService) {}

    @Query('product')
    @Authenticate({ optional: true })
    product(@CurrentUser() user: User | null, @Args('id') id: string) {
      return this.productsService.findOne(user, id);
    }

    @Query('products')
    @Authenticate({ optional: true })
    products(@CurrentUser() user: User | null) {
      return this.productsService.findAll(user);
    }

    @Mutation('createProduct')
    @Can(ProductPolicy, 'create')
    createProduct(@Args('name') name: string) {
      return this.productsService.create({ name, price: 1000, published: false });
    }

    @Mutation('deleteProduct')
    @Authenticate({ optional: true })
    @Can(ProductPolicy, 'delete')
    deleteProduct() {
      return true;
    }
  }

  @Module({
    imports: [
      authenticationModule(),
      AuthorizationModule.forRoot(),
      AuthModule,
      GraphQLModule.forRoot<ApolloDriverConfig>({
        driver: ApolloDriver,
        typeDefs: /* GraphQL */ `
          type Product { id: ID!, name: String!, published: Boolean! }
          type Query { product(id: ID!): Product, products: [Product!]! }
          type Mutation { createProduct(name: String!): Product, deleteProduct: Boolean }
        `,
        context: ({ req }: { req: unknown }) => ({ req }),
      }),
    ],
    providers: [ProductsResolver, ProductsService, ProductPolicy],
  })
  class GqlAppModule {}

  let app: INestApplication;
  const events: AuthorizationDeniedEvent[] = [];
  const bearer = async (user: User) => `Bearer ${(await app.get(TokenService).issue(user.id)).accessToken}`;
  const gql = async (query: string, user?: User) => {
    const call = request(app.getHttpServer()).post('/graphql');
    if (user) {
      call.set('Authorization', await bearer(user));
    }
    return (await call.send({ query }).expect(200)).body;
  };

  beforeAll(async () => {
    app = await createApp('express', GqlAppModule, withCheapHasher);
    app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));
  });
  afterAll(() => app.close());
  beforeEach(() => {
    events.length = 0;
  });

  it('@Can() on a mutation sees the user authentication read from context.req', async () => {
    expect((await gql('mutation { createProduct(name: "Denied") { id } }', alice)).errors[0]).toMatchObject({
      message: 'Forbidden',
      extensions: { code: 'FORBIDDEN' },
    });
    expect((await gql('mutation { createProduct(name: "Cat Wand") { id } }', sam)).data).toEqual({ createProduct: { id: 'cat-wand' } });
    expect((await gql('mutation { deleteProduct }', ada)).data).toEqual({ deleteProduct: true });

    expect(events).toEqual([
      { type: 'denied', policy: 'ProductPolicy', ability: 'create', reason: 'forbidden', user: alice, args: [], handler: 'ProductsResolver.createProduct' },
    ]);
  });

  it('answers anonymous operations: authentication first, then the policy with null on optional ones', async () => {
    expect((await gql('mutation { createProduct(name: "Anon") { id } }')).errors[0]).toMatchObject({
      extensions: { code: 'UNAUTHENTICATED' },
    });
    expect(events).toEqual([]);

    expect((await gql('mutation { deleteProduct }')).errors[0]).toMatchObject({
      message: 'Unauthorized',
      extensions: { code: 'UNAUTHENTICATED' },
    });
    expect(events).toEqual([expect.objectContaining({ ability: 'delete', reason: 'unauthenticated', user: null })]);
  });

  it('maps authorize() in the service per caller, and can() shapes the list', async () => {
    const draft = '{ product(id: "heated-cat-bed") { name } }';
    expect((await gql(draft)).errors[0]).toMatchObject({ extensions: { code: 'UNAUTHENTICATED' } });
    expect((await gql(draft, alice)).errors[0]).toMatchObject({ message: 'Forbidden', extensions: { code: 'FORBIDDEN' } });
    expect((await gql(draft, sam)).data).toEqual({ product: { name: 'Heated Cat Bed' } });

    const names = async (user?: User) => ((await gql('{ products { published } }', user)).data.products as Product[]).map((b) => b.published);
    expect(await names()).not.toContain(false);
    expect(await names(sam)).toContain(false);
  });
});

describe('WebSockets (platform-ws) with @nestjs/authentication', () => {
  @WebSocketGateway({ path: '/products' })
  class ProductsGateway implements OnGatewayConnection {
    constructor(
      private readonly wsAuth: WsAuthenticator,
      private readonly productsService: ProductsService,
    ) {}

    async handleConnection(client: WebSocket, request: IncomingMessage) {
      await this.wsAuth.authenticateConnection(client, request, { required: false });
    }

    @SubscribeMessage('create')
    @Can(ProductPolicy, 'create')
    create(@MessageBody() body: { name: string }) {
      return { event: 'created', data: this.productsService.create({ name: body.name, price: 1000, published: false }).id };
    }

    @SubscribeMessage('delete')
    @Authenticate({ optional: true })
    @Can(ProductPolicy, 'delete')
    remove() {
      return { event: 'deleted', data: true };
    }

    @SubscribeMessage('show')
    @Authenticate({ optional: true })
    async show(@CurrentUser() user: User | null, @MessageBody() body: { id: string }) {
      return { event: 'product', data: (await this.productsService.findOne(user, body.id)).name };
    }
  }

  @Module({
    imports: [authenticationModule(), AuthorizationModule.forRoot(), AuthModule],
    providers: [ProductsGateway, ProductsService, ProductPolicy],
  })
  class WsAppModule {}

  let app: INestApplication;
  let base: string;
  const sockets: WebSocket[] = [];
  const events: AuthorizationDeniedEvent[] = [];

  /** Connects with the user's bearer token in the handshake, sends one message and returns the reply. */
  const ask = async (user: User | null, event: string, data: object = {}) => {
    const headers: Record<string, string> = user ? { authorization: `Bearer ${(await app.get(TokenService).issue(user.id)).accessToken}` } : {};
    const socket = new WebSocket(`${base}/products`, { headers });
    sockets.push(socket);
    await new Promise((resolve, reject) => socket.once('open', resolve).once('error', reject));
    const reply = new Promise<unknown>((resolve) => socket.once('message', (raw) => resolve(JSON.parse(String(raw)))));
    socket.send(JSON.stringify({ event, data }));
    return reply;
  };
  const exception = (message: string, statusCode: number) => ({ event: 'exception', data: { status: 'error', message, statusCode } });
  const unauthenticated = { event: 'exception', data: { status: 'error', message: 'Unauthorized', statusCode: 401, code: 'missing_credentials' } };

  beforeAll(async () => {
    app = await createApp('express', WsAppModule, { ...withCheapHasher, setup: (a) => void a.useWebSocketAdapter(new WsAdapter(a)) });
    base = `ws://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
    app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));
  });
  afterEach(() => {
    sockets.splice(0).forEach((socket) => socket.close());
    events.length = 0;
  });
  afterAll(() => app.close());

  it('@Can() reads client.user, which authentication sets from the handshake', async () => {
    expect(await ask(sam, 'create', { name: 'Laser Pointer' })).toEqual({ event: 'created', data: 'laser-pointer' });
    expect(await ask(alice, 'create', { name: 'Laser Pointer' })).toEqual(exception('Forbidden', 403));
    expect(await ask(ada, 'delete')).toEqual({ event: 'deleted', data: true });

    expect(events).toEqual([
      { type: 'denied', policy: 'ProductPolicy', ability: 'create', reason: 'forbidden', user: alice, args: [], handler: 'ProductsGateway.create' },
    ]);
  });

  it('answers a guest from authentication on required messages, and from the policy on optional ones', async () => {
    expect(await ask(null, 'create', { name: 'Anon' })).toEqual(unauthenticated);
    expect(events).toEqual([]);

    expect(await ask(null, 'delete')).toEqual(exception('Unauthorized', 401));
    expect(events).toEqual([expect.objectContaining({ ability: 'delete', reason: 'unauthenticated', handler: 'ProductsGateway.remove' })]);
  });

  it('turns authorize() denials in a service into ws exceptions', async () => {
    expect(await ask(null, 'show', { id: 'heated-cat-bed' })).toEqual(exception('Unauthorized', 401));
    expect(await ask(alice, 'show', { id: 'heated-cat-bed' })).toEqual(exception('Forbidden', 403));
    expect(await ask(sam, 'show', { id: 'heated-cat-bed' })).toEqual({ event: 'product', data: 'Heated Cat Bed' });
  });
});

describe('TCP microservice with @nestjs/authentication', () => {
  const byToken: Record<string, User> = { 'alice-token': alice, 'sam-token': sam };

  /** Reading credentials from RPC is left to providers: this one reads a token the producer signs. */
  @Injectable()
  class ServiceTokenAuth extends AuthenticationProvider<User> {
    constructor(registry: AuthenticationRegistry) {
      super();
      registry.registerProvider(this);
    }

    authenticate(context: ExecutionContext): AuthenticationResult<User> | null {
      const user = byToken[context.switchToRpc().getData()?.token];
      return user ? { user } : null;
    }
  }

  @Controller()
  class OrdersMessages {
    constructor(private readonly ordersService: OrdersService) {}

    @MessagePattern('orders.refund')
    refund(@CurrentUser() user: User, @Payload() data: { id: string }) {
      return this.ordersService.refund(user, data.id);
    }

    @MessagePattern('products.delete')
    @Authenticate({ optional: true })
    @Can(ProductPolicy, 'delete')
    deleteProduct() {
      return true;
    }
  }

  @Module({
    imports: [AuthenticationModule.forRoot(), AuthorizationModule.forRoot()],
    controllers: [OrdersMessages],
    providers: [ServiceTokenAuth, OrdersService, OrderPolicy, RefundLimitsService, ProductPolicy],
  })
  class RpcAppModule {}

  let app: INestMicroservice;
  let client: ClientProxy;
  const send = (pattern: string, data: object) =>
    lastValueFrom(client.send(pattern, data)).then(
      (reply: unknown) => ({ reply }),
      (error: unknown) => ({ error }),
    );

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [RpcAppModule] }).compile();
    app = moduleRef.createNestMicroservice({ transport: Transport.TCP, options: { host: '127.0.0.1', port: 0 } });
    await app.listen();

    const { port } = app.unwrap<NetServer>().address() as AddressInfo;
    client = ClientProxyFactory.create({ transport: Transport.TCP, options: { host: '127.0.0.1', port } });
    await client.connect();
  });
  afterAll(async () => {
    await client.close();
    await app.close();
  });

  it('checks record abilities in a service for the caller authentication put on the transport context', async () => {
    expect(await send('orders.refund', { token: 'alice-token', id: alicePaid.id })).toEqual({
      error: { message: 'Forbidden', statusCode: 403 },
    });
    expect(await send('orders.refund', { token: 'sam-token', id: bobPaid.id })).toEqual({
      error: { message: 'Forbidden', statusCode: 403 },
    });
    expect(await send('orders.refund', { token: 'sam-token', id: alicePaid.id })).toMatchObject({
      reply: { id: alicePaid.id, status: 'refunded' },
    });
  });

  it('answers a guest from authentication on required handlers, and from @Can() on optional ones', async () => {
    expect(await send('orders.refund', { id: alicePaid.id })).toEqual({
      error: { message: 'Unauthorized', statusCode: 401, code: 'missing_credentials' },
    });
    expect(await send('products.delete', {})).toEqual({ error: { message: 'Unauthorized', statusCode: 401 } });
    expect(await send('products.delete', { token: 'sam-token' })).toEqual({ error: { message: 'Forbidden', statusCode: 403 } });
  });
});
