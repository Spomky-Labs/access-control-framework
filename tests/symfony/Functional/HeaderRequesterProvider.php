<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Requester\RequesterProviderInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Reads the roles off a header, so that one application can be asked the same question as several
 * different requesters. An application would read them from wherever it keeps them.
 *
 * The access rule listener runs on kernel.request, by which point HttpKernel has pushed the request
 * onto the stack, so the requester is already knowable there.
 */
final readonly class HeaderRequesterProvider implements RequesterProviderInterface
{
    public function __construct(
        private RequestStack $requestStack,
    ) {
    }

    public function getRequester(): ?RolesRequester
    {
        $roles = $this->requestStack->getCurrentRequest()?->headers
            ->get('X-Roles');

        if ($roles === null || $roles === '') {
            return null;
        }

        return new RolesRequester(explode(',', $roles));
    }
}
