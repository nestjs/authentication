import type { ExecutionContext } from '@nestjs/common';

/**
 * @internal The context object of a GraphQL operation, read from the resolver
 * args positionally so this package needs no `@nestjs/graphql` dependency:
 * the third of `(root, args, context, info)`, or the second of a federation
 * reference resolver's `(reference, context, info)`. `@nestjs/graphql` tells
 * them apart by the count too. In the first form, the second argument holds
 * the client's arguments, so it is read only in the second.
 */
export function graphqlContextOf(context: ExecutionContext): Record<PropertyKey, any> | undefined {
  const operation = context.getArgByIndex(context.getArgs().length === 3 ? 1 : 2);
  return typeof operation === 'object' && operation !== null ? operation : undefined;
}
