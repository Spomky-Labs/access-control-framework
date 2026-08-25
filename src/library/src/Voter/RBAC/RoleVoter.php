<?php

declare(strict_types=1);

namespace AccessControl\Voter\RBAC;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use function in_array;
use function is_object;
use function is_string;

final readonly class RoleVoter implements VoterInterface
{
    public function __construct(
        private ?RoleHierarchyInterface $roleHierarchy = null,
        private string $prefix = 'ROLE_',
    ) {
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! $this->supportsAttribute($accessRequest->attribute)) {
            return AccessOutcome::abstain('The attribute is not a role.');
        }

        if (in_array($accessRequest->attribute, $this->extractRoles($accessRequest->requester), true)) {
            return AccessOutcome::grant('The user has the required role.');
        }

        return AccessOutcome::deny('The user does not have the required role.');
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return is_string($attribute) && str_starts_with($attribute, $this->prefix);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    /**
     * @return list<string>
     */
    private function extractRoles(mixed $requester): array
    {
        $roles = [];

        if ($requester instanceof TokenInterface) {
            $roles = $requester->getRoleNames();
        } elseif ($requester instanceof UserWithRoleInterface || (is_object($requester) && method_exists($requester, 'getRoles'))) {
            $roles = $requester->getRoles();
        }

        return $this->roleHierarchy?->getReachableRoleNames($roles) ?? $roles;
    }
}
