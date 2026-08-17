<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Voter\RBAC\UserWithRoleInterface;

/**
 * A requester in an application that has no Security, so no token and no user provider.
 */
final readonly class RolesRequester implements UserWithRoleInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(
        private array $roles,
    ) {
    }

    public function getRoles(): array
    {
        return $this->roles;
    }
}
