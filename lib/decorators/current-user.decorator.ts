import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import { resultOf } from '../utils/auth-state.util.js';
import type { AuthenticatedUser } from '../interfaces/authentication-result.interface.js';

/**
 * The authenticated user, or `null` on `@Public()` and anonymous optional
 * calls. `@CurrentUser('email')` picks one property; the key is checked
 * against the `AuthenticationTypes` augmentation.
 */
// Annotated so the emitted .d.ts keeps `keyof AuthenticatedUser`: inferred, it
// is resolved at build time against the unaugmented user and becomes `string`.
export const CurrentUser: ReturnType<
  typeof createParamDecorator<keyof AuthenticatedUser | undefined>
> = createParamDecorator<keyof AuthenticatedUser | undefined>(
  (key, context: ExecutionContext) => {
    const user = resultOf(context)?.user ?? null;
    return key && user ? user[key] : user;
  },
);
