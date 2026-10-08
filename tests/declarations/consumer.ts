import { CurrentUser } from '@nestjs/authentication';
import type { PipeTransform } from '@nestjs/common';

// Compile-time checks against the built declarations in `dist`, as a consumer
// sees them. Verified by `tsc -p tests/declarations` after `npm run build`.

declare module '@nestjs/authentication' {
  interface AuthenticationTypes {
    user: { id: string; email: string };
  }
}

class TrimPipe implements PipeTransform {
  transform(value: unknown) {
    return value;
  }
}

export class Handlers {
  user(@CurrentUser() user: unknown) {
    return user;
  }

  id(@CurrentUser('id') id: string) {
    return id;
  }

  email(@CurrentUser('email', TrimPipe) email: string) {
    return email;
  }

  // @ts-expect-error 'notAUserKey' is not a key of the augmented user
  typo(@CurrentUser('notAUserKey') value: unknown) {
    return value;
  }
}
