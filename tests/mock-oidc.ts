import { createHash, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { JwtSigner, type JwsAlgorithm } from '../lib/index.js';

interface Grant {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  nonce?: string;
  sub: string;
  idToken: Record<string, unknown>;
  alg: JwsAlgorithm;
  kid?: string;
  signWith?: KeyObject;
  userinfoSub?: string;
}

export interface ApproveOptions {
  sub: string;
  /** Overrides for ID token claims (aud, nonce, exp, …). */
  idToken?: Record<string, unknown>;
  alg?: 'RS256' | 'ES256';
  /** Sign with a key the JWKS does not publish (under the published kid). */
  signWith?: KeyObject;
  /** Userinfo answers for a different subject. */
  userinfoSub?: string;
  /** Replace the PKCE challenge the client sent. */
  codeChallenge?: string;
}

/**
 * A minimal OpenID Provider on node:http: discovery, JWKS, token endpoint
 * (client_secret_basic, client_secret_post or a public client; PKCE S256, redirect_uri and
 * single-use code checks),
 * userinfo, plus GitHub-style OAuth 2.0 endpoints under /gh.
 */
export class MockOidcProvider {
  readonly clientId = 'nest-client';
  readonly clientSecret = 's3cr3t:with/special+chars';
  /** A public client (PKCE only, no secret). */
  readonly publicClientId = 'nest-public-client';
  /** More confidential clients, one per tenant, by id: their secret, which a test may rotate. */
  readonly clients = new Map<string, string>();
  /** How each accepted token request authenticated the client. */
  readonly clientAuthentications: ('client_secret_basic' | 'client_secret_post' | 'none')[] = [];
  issuer = '';
  private server?: Server;
  private rsa = { ...generateKeyPairSync('rsa', { modulusLength: 2048 }), kid: 'rsa-1' };
  private readonly ec = { ...generateKeyPairSync('ec', { namedCurve: 'P-256' }), kid: 'ec-1' };
  private readonly codes = new Map<string, Grant>();
  private readonly accessTokens = new Map<string, Grant | 'github'>();
  jwksRequests = 0;
  discoveryRequests = 0;
  /** An endpoint that answers 503, as during an outage. */
  down?: 'token' | 'userinfo';

  async start() {
    this.server = createServer((req, res) => {
      this.handle(req)
        .then(({ status, body }) => {
          res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
        })
        .catch((error) => res.writeHead(500).end(String(error)));
    });

    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    this.issuer = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  stop() {
    return new Promise((resolve) => this.server?.close(resolve));
  }

  rotateRsaKey() {
    this.rsa = { ...generateKeyPairSync('rsa', { modulusLength: 2048 }), kid: `rsa-${Date.now()}` };
  }

  /** The user approves the authorization request at `authorizeUrl`; returns the code. */
  approve(authorizeUrl: string, options: ApproveOptions): string {
    const params = new URL(authorizeUrl).searchParams;
    const code = randomBytes(16).toString('hex');

    this.codes.set(code, {
      clientId: params.get('client_id')!,
      redirectUri: params.get('redirect_uri')!,
      codeChallenge: options.codeChallenge ?? params.get('code_challenge')!,
      nonce: params.get('nonce') ?? undefined,
      sub: options.sub,
      idToken: options.idToken ?? {},
      alg: options.alg ?? 'RS256',
      signWith: options.signWith,
      userinfoSub: options.userinfoSub,
    });

    return code;
  }

  private async handle(req: IncomingMessage): Promise<{ status: number; body: unknown }> {
    const url = new URL(req.url!, this.issuer);
    if (this.down && url.pathname === `/${this.down}`) {
      return { status: 503, body: 'Service Unavailable' };
    }

    switch (`${req.method} ${url.pathname}`) {
      case 'GET /.well-known/openid-configuration':
        this.discoveryRequests++;
        return {
          status: 200,
          body: {
            issuer: this.issuer,
            authorization_endpoint: `${this.issuer}/authorize`,
            token_endpoint: `${this.issuer}/token`,
            userinfo_endpoint: `${this.issuer}/userinfo`,
            jwks_uri: `${this.issuer}/jwks`,
            code_challenge_methods_supported: ['S256'],
            id_token_signing_alg_values_supported: ['RS256', 'ES256'],
          },
        };
      case 'GET /jwks':
        this.jwksRequests++;
        return {
          status: 200,
          body: {
            keys: [
              { ...this.rsa.publicKey.export({ format: 'jwk' }), kid: this.rsa.kid, use: 'sig', alg: 'RS256' },
              { ...this.ec.publicKey.export({ format: 'jwk' }), kid: this.ec.kid, use: 'sig', alg: 'ES256' },
            ],
          },
        };
      case 'POST /token':
        return this.token(req, url);
      case 'GET /userinfo': {
        const grant = this.accessTokens.get(bearer(req));
        if (!grant || grant === 'github') {
          return { status: 401, body: { error: 'invalid_token' } };
        }
        return {
          status: 200,
          body: { sub: grant.userinfoSub ?? grant.sub, email: `${grant.sub}@idp.test`, email_verified: true, name: 'From Userinfo' },
        };
      }
      case 'POST /gh/token': {
        const form = new URLSearchParams(await body(req));
        const grant = this.codes.get(form.get('code') ?? '');
        this.codes.delete(form.get('code') ?? '');
        if (!grant) {
          return { status: 200, body: { error: 'bad_verification_code' } }; // GitHub answers 200
        }

        const token = randomBytes(16).toString('hex');
        this.accessTokens.set(token, 'github');
        return { status: 200, body: { access_token: token, token_type: 'bearer', scope: 'read:user,user:email' } };
      }
      case 'GET /gh/user':
        if (this.accessTokens.get(bearer(req)) !== 'github') {
          return { status: 401, body: {} };
        }
        return { status: 200, body: { id: 4242, login: 'octocat', name: null, email: 'public@unverified.test' } };
      case 'GET /gh/user/emails':
        if (this.accessTokens.get(bearer(req)) !== 'github') {
          return { status: 401, body: {} };
        }
        return {
          status: 200,
          body: [
            { email: 'old@example.com', primary: false, verified: true },
            { email: 'octo@example.com', primary: true, verified: true },
          ],
        };
      default:
        return { status: 404, body: { error: 'not_found' } };
    }
  }

  private async token(req: IncomingMessage, _url: URL) {
    const form = new URLSearchParams(await body(req));
    const basic = req.headers.authorization?.startsWith('Basic ');
    const [id, secret] = basic
      ? Buffer.from(req.headers.authorization!.replace(/^Basic /, ''), 'base64')
          .toString()
          .split(':')
          .map(decodeURIComponent)
      : [form.get('client_id') ?? '', form.get('client_secret') ?? undefined];
    const method = basic ? 'client_secret_basic' : secret === undefined ? 'none' : 'client_secret_post';
    const publicClient = method === 'none' && id === this.publicClientId;
    const expected = id === this.clientId ? this.clientSecret : this.clients.get(id);
    if (!publicClient && (expected === undefined || secret !== expected)) {
      return { status: 401, body: { error: 'invalid_client' } };
    }
    this.clientAuthentications.push(method);

    const grant = this.codes.get(form.get('code') ?? '');
    this.codes.delete(form.get('code') ?? ''); // single use
    if (!grant || grant.clientId !== id || grant.redirectUri !== form.get('redirect_uri')) {
      return { status: 400, body: { error: 'invalid_grant' } };
    }
    const challenge = createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url');
    if (challenge !== grant.codeChallenge) {
      return { status: 400, body: { error: 'invalid_grant', error_description: 'PKCE' } };
    }

    const accessToken = randomBytes(16).toString('hex');
    this.accessTokens.set(accessToken, grant);

    const key = grant.alg === 'ES256' ? this.ec : this.rsa;
    // Tokens live 300 s; a test that sets `exp` (in the past, say) moves the issue time with it.
    const exp = typeof grant.idToken.exp === 'number' ? grant.idToken.exp : Math.floor(Date.now() / 1000) + 300;
    const signer = new JwtSigner({
      key: grant.signWith ?? key.privateKey,
      alg: grant.alg,
      kid: key.kid,
      ttl: '300s',
      now: () => (exp - 300) * 1000,
    });

    const idToken = signer.sign({
      iss: this.issuer,
      aud: grant.clientId,
      sub: grant.sub,
      nonce: grant.nonce,
      email: `${grant.sub}@idp.test`,
      email_verified: true,
      ...grant.idToken,
    });
    return { status: 200, body: { access_token: accessToken, token_type: 'Bearer', expires_in: 300, id_token: idToken } };
  }
}

function bearer(req: IncomingMessage) {
  return (req.headers.authorization ?? '').replace(/^Bearer /, '');
}

async function body(req: IncomingMessage): Promise<string> {
  let data = '';
  for await (const chunk of req) {
    data += chunk;
  }
  return data;
}
