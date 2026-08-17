<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface AccessPolicyInterface
{
    public ?string $message { get; }
}
