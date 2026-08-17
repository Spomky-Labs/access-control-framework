<?php

declare(strict_types=1);

namespace AccessControl;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface AccessControlManagerInterface
{
    public function decide(AccessRequest $accessRequest, ?string $strategy = null): AccessDecision;
}
