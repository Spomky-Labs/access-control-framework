<?php

declare(strict_types=1);

namespace AccessControl\Exception;

use RuntimeException;
use Symfony\Component\HttpKernel\Attribute\WithHttpStatus;

/**
 * The status code is what an application without a firewall answers on a denial, HttpKernel's error
 * listener reading the attribute. Behind a firewall the exception listener decides instead, and may
 * redirect to the login page rather than answer 403.
 */
#[WithHttpStatus(403)]
class AccessDeniedException extends RuntimeException implements AccessDeniedExceptionInterface
{
}
