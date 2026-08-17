<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface CompositeAccessPolicyInterface extends AccessPolicyInterface
{
    /**
     * @var list<AccessPolicyInterface>
     */
    public array $accessPolicies { get; }
}
