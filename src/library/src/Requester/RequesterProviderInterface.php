<?php

declare(strict_types=1);

namespace AccessControl\Requester;

/**
 * Tells who is currently asking for access, whatever the execution context is.
 *
 * @experimental
 */
interface RequesterProviderInterface
{
    public function getRequester(): mixed;
}
