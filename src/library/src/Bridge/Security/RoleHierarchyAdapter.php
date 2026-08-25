<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Security;

use AccessControl\Voter\RBAC\RoleHierarchyInterface;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface as SecurityRoleHierarchyInterface;

/**
 * Lets the component's voters read the hierarchy Security already built.
 *
 * Both stacks derive their hierarchy from the same security.role_hierarchy configuration, so having
 * two objects would mean the same tree walked twice and free to drift. One object serves both, and
 * an application that replaced security.role_hierarchy with its own is honoured here too.
 *
 * The adapter goes this way round and not the other: putting the component's implementation behind
 * security.role_hierarchy would break every application typed against Security's interface, which
 * the component does not implement and must not, the notion of role being on its way out of there.
 */
final readonly class RoleHierarchyAdapter implements RoleHierarchyInterface
{
    public function __construct(
        private SecurityRoleHierarchyInterface $roleHierarchy,
    ) {
    }

    /**
     * Security's own shape is not this contract's, and it has changed within a minor: 8.1.0 hands
     * back an array keyed by role name, 8.1.4 a list. Passing it through made this adapter answer
     * something its interface says is a list, silently, on whichever patch an application installed.
     */
    public function getReachableRoleNames(array $roles): array
    {
        return array_values($this->roleHierarchy->getReachableRoleNames($roles));
    }
}
