<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
#[\Attribute(\Attribute::IS_REPEATABLE | \Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION)]
readonly class AccessPolicy implements AccessPolicyInterface
{
    /**
     * @param array<array-key, mixed> $environment
     */
    public function __construct(
        public mixed $attribute,
        public mixed $subject = null,
        public ?string $strategy = null,
        public array $environment = [],
        /**
         * Null defers to the manager, where an application settles it once for the whole of itself.
         */
        public ?bool $allowIfAllAbstain = null,
        public ?string $message = null,
    ) {
    }
}
