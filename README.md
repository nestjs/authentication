<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

  <p align="center">A progressive <a href="http://nodejs.org" target="blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore"><img src="https://img.shields.io/npm/dm/@nestjs/core.svg" alt="NPM Downloads" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec"><img src="https://img.shields.io/badge/Donate-PayPal-dc3d53.svg"/></a>
  <a href="https://twitter.com/nestframework"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Description

Authentication module for [Nest](https://github.com/nestjs/nest): a global guard with `@Public()` and `@Authenticate()`, credential providers as ordinary injectable classes (bearer JWT, cookie sessions, your own), server-side sessions with rotation, refresh tokens, TOTP second factor, magic links, OIDC sign-in, email verification and password reset, across HTTP, GraphQL, WebSockets and microservices, with no third-party dependencies.

## Installation

```bash
$ npm i --save @nestjs/authentication
```

## Quick Start

Import the module. Its global guard then requires a signed-in user on every route:

```ts
@Module({
  imports: [
    AuthenticationModule.forRoot({
      accessToken: {
        key: process.env.JWT_SECRET!,
        issuer: 'https://api.example.com',
        audience: 'web',
        ttl: '15m',
      },
    }),
  ],
  providers: [JwtAuth],
})
export class AppModule {}
```

Credential providers are ordinary injectable classes that register themselves with `AuthenticationRegistry`:

```ts
@Injectable()
export class JwtAuth extends JwtBearerProvider<User> {
  constructor(
    private readonly users: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super(); // verifies the tokens the module's `accessToken` option signs
    registry.registerProvider(this);
  }

  validate({ sub }: JwtClaims) {
    return sub ? this.users.findById(sub) : null;
  }
}
```

Then use `@Public()` to opt a route out, and `@Authenticate()` to change what a route requires:

```ts
@Controller()
export class AppController {
  @Public()
  @Get('health')
  health() {
    return 'ok';
  }

  @Get('me')
  me(@CurrentUser() user: User) {
    return user;
  }

  // Anonymous callers get through too: `user` is then `null`.
  @Authenticate({ optional: true })
  @Get('greeting')
  greeting(@CurrentUser() user: User | null) {
    return user ? `Hello, ${user.email}` : 'Hello, guest';
  }
}
```

The in-memory stores are fine in development. In production, startup fails until you register real stores with `AuthenticationStorage.registerSource()` for everything your features use (a `SessionCookieProvider` uses the `sessions` store, `accessToken` the `refreshTokens` store, and `mfa`, off unless configured, the `mfa` store), or you set `allowInMemoryStorage: true`. Read [Overview & Tutorial](https://docs.nestjs.com/security/authentication) for sessions, refresh tokens, TOTP, magic links, OIDC and account flows.

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](LICENSE).
