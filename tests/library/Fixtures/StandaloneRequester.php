<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Voter\RBAC\UserWithRoleInterface;

final readonly class StandaloneRequester implements UserWithRoleInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(
        private array $roles = ['ROLE_ADMIN'],
    ) {
    }

    public function getRoles(): array
    {
        return $this->roles;
    }
}
