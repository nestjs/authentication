/**
 * The docs' rate-limiting recipe with `@nestjs/throttler`, on Express and Fastify: two throttler
 * definitions, `default` per IP on every route and `account` per (email, IP) where the body names
 * an account, so both limits apply; `@Throttle()` on the sign-in and password-reset routes (the
 * latter per address alone); and guessed credentials on protected routes counted too, because
 * the throttler runs before the authentication guard.
 */
import { Body, Controller, Get, HttpCode, Injectable, Module, Post, UnauthorizedException } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Throttle, ThrottlerGuard, ThrottlerModule, minutes, normalizeIp } from '@nestjs/throttler';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  JwtBearerProvider,
  PasswordResetHandler,
  PasswordResetService,
  Public,
  SignInService,
  type JwtClaims,
  type PasswordResetLink,
} from '../lib/index.js';

const PASSWORD = 'correct horse battery staple';

/** The address the request body names, trimmed, lowercased and in Unicode NFC, or `''`. */
function accountEmail(req: { body?: { email?: unknown } }): string {
  const email = req.body?.email;
  return typeof email === 'string' ? email.trim().normalize('NFC').toLowerCase() : '';
}

@Injectable()
class JwtAuth extends JwtBearerProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(claims: JwtClaims) {
    return { id: claims.sub! };
  }
}

@Injectable()
class ResetMailer extends PasswordResetHandler {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerHandler('passwordReset', this);
  }
  findUser() {
    return null;
  }
  send(_link: PasswordResetLink) {}
  updatePassword() {}
}

@Controller()
class AuthController {
  constructor(
    private readonly signInService: SignInService,
    private readonly passwordResetService: PasswordResetService,
  ) {}

  @Public()
  @Throttle({ default: { limit: 8, ttl: minutes(15) }, account: { limit: 5, ttl: minutes(15) } })
  @Post('auth/login')
  @HttpCode(200)
  async login(@Body() body: { email: string; password: string }) {
    if (body.password !== PASSWORD) {
      throw new UnauthorizedException('Invalid email or password');
    }
    await this.signInService.signIn(body.email.trim().toLowerCase(), { method: 'password' });
  }

  @Public()
  @Throttle({ default: { limit: 6, ttl: minutes(15) }, account: { limit: 3, ttl: minutes(15), getTracker: accountEmail } })
  @Post('auth/password/forgot')
  @HttpCode(202)
  forgot(@Body('email') email: string) {
    this.passwordResetService.request(email);
  }

  @Get('orders')
  orders(@CurrentUser('id') id: string) {
    return { id };
  }
}

@Module({
  imports: [
    ThrottlerModule.forRoot([
      // Per IP, on every route.
      { name: 'default', ttl: minutes(1), limit: 10 },
      // Per (email, IP), wherever the request body names an account.
      {
        name: 'account',
        ttl: minutes(15),
        limit: 5,
        skipIf: (context) => !accountEmail(context.switchToHttp().getRequest()),
        getTracker: (req) => `${accountEmail(req)}|${normalizeIp(req.ip)}`,
      },
    ]),
    AuthenticationModule.forRoot({
      accessToken: { key: 'throttler-test-secret-of-at-least-32-bytes' },
      passwordReset: { url: 'https://example.com/reset-password' },
    }),
  ],
  controllers: [AuthController],
  // In the root module, so it runs before the authentication guard.
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }, JwtAuth, ResetMailer],
})
class AppModule {}

describe.each(adapters.map((a) => a.name))('rate limiting with @nestjs/throttler (%s)', (adapter) => {
  let app: Awaited<ReturnType<typeof createApp>>;
  const http = () => request(app.getHttpServer());

  beforeEach(async () => {
    app = await createApp(adapter, AppModule);
  });
  afterEach(() => app.close());

  it('limits sign-in attempts per account and IP, the right password included', async () => {
    for (let attempt = 0; attempt < 5; attempt++) {
      await http().post('/auth/login').send({ email: 'ada@example.com', password: 'guess' }).expect(401);
    }

    const limited = await http().post('/auth/login').send({ email: ' ADA@example.com ', password: PASSWORD }).expect(429);
    // A named throttler other than `default` suffixes its headers with its name.
    expect(limited.headers['retry-after-account']).toBeDefined();
    expect(limited.headers['set-cookie']).toBeUndefined();

    await http().post('/auth/login').send({ email: 'grace@example.com', password: PASSWORD }).expect(200);
  });

  it('keeps the limit per IP when every sign-in attempt names another account', async () => {
    for (let attempt = 0; attempt < 8; attempt++) {
      await http().post('/auth/login').send({ email: `user${attempt}@example.com`, password: 'guess' }).expect(401);
    }

    await http().post('/auth/login').send({ email: 'user8@example.com', password: 'guess' }).expect(429);
  });

  it('limits password reset requests per address', async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      await http().post('/auth/password/forgot').send({ email: 'ada@example.com' }).expect(202);
    }

    await http().post('/auth/password/forgot').send({ email: 'ada@example.com' }).expect(429);
    await http().post('/auth/password/forgot').send({ email: 'grace@example.com' }).expect(202);
  });

  it('keeps the limit per IP when every password reset request names another address', async () => {
    for (let attempt = 0; attempt < 6; attempt++) {
      await http().post('/auth/password/forgot').send({ email: `user${attempt}@example.com` }).expect(202);
    }

    await http().post('/auth/password/forgot').send({ email: 'user6@example.com' }).expect(429);
  });

  it('counts guessed bearer tokens on protected routes: the throttler answers before the authentication guard', async () => {
    for (let attempt = 0; attempt < 10; attempt++) {
      const res = await http().get('/orders').set('Authorization', `Bearer guess-${attempt}`).expect(401);
      expect(res.headers['www-authenticate']).toMatch(/^Bearer realm="api", error="invalid_token"/);
    }

    const limited = await http().get('/orders').set('Authorization', 'Bearer guess-10').expect(429);
    expect(limited.headers['www-authenticate']).toBeUndefined();
  });
});
