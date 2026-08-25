<?php

declare(strict_types=1);

namespace AccessControl\Requester;

/**
 * Always hands over the same requester, typically a service account in a console context.
 */
final readonly class StaticRequesterProvider implements RequesterProviderInterface
{
    public function __construct(
        private mixed $requester = null,
    ) {
    }

    public function getRequester(): mixed
    {
        return $this->requester;
    }
}
