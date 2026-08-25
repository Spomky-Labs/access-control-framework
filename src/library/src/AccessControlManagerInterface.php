<?php

declare(strict_types=1);

namespace AccessControl;

/**
 * @experimental
 */
interface AccessControlManagerInterface
{
    public function decide(AccessRequest $accessRequest, ?string $strategy = null): AccessDecision;
}
