<?php

declare(strict_types=1);

namespace AccessControl\Exception;

/**
 * Marks an exception as an access denial, whichever component threw it.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface AccessDeniedExceptionInterface extends \Throwable
{
}
