<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Attribute\AccessPolicyInterface;
use Attribute;

#[Attribute(Attribute::IS_REPEATABLE | Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class Inapplicable implements AccessPolicyInterface
{
    public function __construct(
        public ?string $message = null,
    ) {
    }
}
