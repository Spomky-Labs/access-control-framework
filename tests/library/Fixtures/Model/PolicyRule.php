<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

final readonly class PolicyRule
{
    /**
     * @param array<string, mixed> $target Requester attributes the rule applies to
     */
    public function __construct(
        public string $attribute,
        public array $target,
        public bool $permit,
        public string $description,
    ) {
    }
}
