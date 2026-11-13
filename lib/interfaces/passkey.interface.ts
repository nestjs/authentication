import type { Duration } from './duration.interface.js';

export interface PasskeyOptions {
  /** The relying party id: the site's domain, e.g. `example.com`. Passkeys work on it and its subdomains. */
  rpId: string;
  /** Shown by the authenticator. */
  rpName: string;
  /** Origins that may register and sign in, e.g. `['https://app.example.com']`. */
  origins: string[];
  /** How long a challenge lasts, and the browser's timeout. Default `'5m'`. */
  timeout?: Duration;
  /** Default `'preferred'`. With `'required'` an assertion without user verification is refused. */
  userVerification?: 'required' | 'preferred' | 'discouraged';
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

/** The account a passkey is registered to. */
export interface PasskeyUser {
  id: string;
  /** Usually the email or username. */
  name: string;
  displayName?: string;
}

/** Options for `navigator.credentials.create({ publicKey })`, in JSON: decode `challenge` and `user.id` from base64url. */
export interface PasskeyRegistrationOptions {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout: number;
  attestation: 'none';
  excludeCredentials: PasskeyDescriptor[];
  authenticatorSelection: {
    residentKey: 'required';
    userVerification: 'required' | 'preferred' | 'discouraged';
  };
}

/** Options for `navigator.credentials.get({ publicKey })`, in JSON. */
export interface PasskeyAuthenticationOptions {
  rpId: string;
  challenge: string;
  timeout: number;
  userVerification: 'required' | 'preferred' | 'discouraged';
  /** Empty: the browser offers the passkeys it holds for this site. */
  allowCredentials: PasskeyDescriptor[];
}

export interface PasskeyDescriptor {
  type: 'public-key';
  id: string;
  transports?: string[];
}

/** What `PublicKeyCredential.toJSON()` returns after `create()`. */
export interface PasskeyRegistrationResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
}

/** What `PublicKeyCredential.toJSON()` returns after `get()`. */
export interface PasskeyAuthenticationResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string | null;
  };
}

export type PasskeyFailure =
  | 'malformed'
  | 'challenge'
  | 'origin'
  | 'rp-id'
  | 'flags'
  | 'attestation'
  | 'key'
  | 'credential'
  | 'user'
  | 'signature'
  | 'counter';
