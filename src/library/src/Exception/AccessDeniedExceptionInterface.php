<?php

declare(strict_types=1);

namespace AccessControl\Exception;

use Throwable;

/**
 * Marks an exception as an access denial, whichever component threw it.
 *
 * @experimental
 */
interface AccessDeniedExceptionInterface extends Throwable
{
}
