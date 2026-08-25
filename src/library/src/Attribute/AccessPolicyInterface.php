<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

interface AccessPolicyInterface
{
    public ?string $message { get; }
}
