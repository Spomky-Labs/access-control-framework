<?php

declare(strict_types=1);

namespace AccessControl\Voter\RBAC;

/**
 * Expands a set of held roles into every role they reach.
 *
 * The counterpart of Security's interface of the same name, and its destination: the notion of
 * role is meant to leave Security, so this component cannot lean on a contract that is going away.
 * The two coexist for the length of the migration, after which Security's is deprecated and its
 * service becomes an alias of ours.
 *
 * The inverse lookup that RoleHierarchy offers is deliberately not announced here, not even as a
 * documented method Symfony would read as forthcoming. Such an announcement is an obligation on
 * every implementation, which DebugClassLoader enforces and which was measured on this component's
 * own adapter. No voter asks the question, so no implementation is put on notice for it.
 */
interface RoleHierarchyInterface
{
    /**
     * @param list<string> $roles
     *
     * @return list<string>
     */
    public function getReachableRoleNames(array $roles): array;
}
