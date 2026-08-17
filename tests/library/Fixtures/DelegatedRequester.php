<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Requester\DelegatedRequesterInterface;
use AccessControl\Voter\RBAC\UserWithRoleInterface;

/**
 * A requester somebody else is acting as, with no token anywhere: the shape an application without
 * Security would have, and the one the contract exists for.
 */
final readonly class DelegatedRequester implements DelegatedRequesterInterface, UserWithRoleInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(
        private mixed $actor,
        private array $roles = [],
    ) {
    }

    public function getActor(): mixed
    {
        return $this->actor;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }
}
