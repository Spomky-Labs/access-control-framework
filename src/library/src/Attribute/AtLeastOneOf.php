<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
#[\Attribute(\Attribute::IS_REPEATABLE | \Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION)]
final readonly class AtLeastOneOf implements CompositeAccessPolicyInterface
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
