<?php

declare(strict_types=1);

namespace AccessControl\Attribute;

/**
 * @experimental
 */
interface CompositeAccessPolicyInterface extends AccessPolicyInterface
{
    /**
     * @var list<AccessPolicyInterface>
     */
    public array $accessPolicies { get; }
}
