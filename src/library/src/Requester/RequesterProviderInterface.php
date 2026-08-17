<?php

declare(strict_types=1);

namespace AccessControl\Requester;

/**
 * Tells who is currently asking for access, whatever the execution context is.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface RequesterProviderInterface
{
    public function getRequester(): mixed;
}
