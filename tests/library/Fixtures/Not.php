<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Attribute\CompositeAccessPolicyInterface;

#[\Attribute(\Attribute::IS_REPEATABLE | \Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION)]
final readonly class Not implements CompositeAccessPolicyInterface
{
    /**
     * @param list<AccessPolicyInterface> $accessPolicies
     */
    public function __construct(
        public array $accessPolicies,
        public ?string $message = null,
    ) {
    }
}
