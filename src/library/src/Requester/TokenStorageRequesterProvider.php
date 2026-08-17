<?php

declare(strict_types=1);

namespace AccessControl\Requester;

use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final readonly class TokenStorageRequesterProvider implements RequesterProviderInterface
{
    public function __construct(
        private TokenStorageInterface $tokenStorage,
    ) {
    }

    public function getRequester(): mixed
    {
        return $this->tokenStorage->getToken();
    }
}
