<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

/**
 * @experimental
 */
interface AccessPolicyInterface
{
    public ?string $message { get; }
}
