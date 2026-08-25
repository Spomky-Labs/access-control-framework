<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

use Attribute;
use Symfony\Component\ExpressionLanguage\Expression;

/**
 * Requires the nested access policies only when the condition holds, and steps aside otherwise.
 *
 * The condition speaks about the circumstances of the call, not about the requester: the entry
 * point hands over its own context, so an HTTP method is reached as request.isMethod("POST") and a
 * console option as input.getOption("force").
 *
 * The condition is an Expression rather than a string, as a bare string would be silently compiled
 * as one, which is the very trap the expression voter had to be fixed for.
 *
 * @experimental
 */
#[Attribute(Attribute::IS_REPEATABLE | Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class When implements CompositeAccessPolicyInterface
{
    /**
     * @param list<AccessPolicyInterface> $accessPolicies
     */
    public function __construct(
        public Expression $condition,
        public array $accessPolicies,
        public ?string $message = null,
    ) {
    }
}
