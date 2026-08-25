<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

/**
 * References a value that is only known at runtime, by name.
 *
 * @experimental
 */
final readonly class Argument
{
    public function __construct(
        public string $name,
    ) {
    }
}
