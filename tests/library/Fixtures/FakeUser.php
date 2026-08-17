<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use Symfony\Component\Security\Core\User\UserInterface;

final readonly class FakeUser implements UserInterface
{
    public function __construct(
        private string $username = 'foo',
        private array $roles = ['ROLE_USER'],
    ) {
    }

    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }
}
