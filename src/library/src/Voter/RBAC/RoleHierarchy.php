<?php

declare(strict_types=1);

namespace AccessControl\Voter\RBAC;

/**
 * Resolves a hierarchy of roles into a map of everything each role reaches, transitively.
 *
 * Behaves exactly as Security's RoleHierarchy, cycles included, so that an application moving over
 * keeps the very same reachable roles. The duplication is deliberate and temporary: the component
 * cannot depend on a service of SecurityBundle for a notion that is leaving Security.
 */
class RoleHierarchy implements RoleHierarchyInterface
{
    /**
     * @var array<string, array<string, string>>
     */
    protected array $map;

    /**
     * @param array<string, list<string>> $hierarchy
     */
    public function __construct(
        private readonly array $hierarchy = [],
    ) {
        $this->buildRoleMap();
    }

    public function getReachableRoleNames(array $roles): array
    {
        $reachableRoles = [];

        foreach ($roles as $role) {
            $reachableRoles[$role] = $role;

            foreach ($this->map[$role] ?? [] as $reachable) {
                $reachableRoles[$reachable] = $reachable;
            }
        }

        return array_values($reachableRoles);
    }

    /**
     * The inverse question: every role that reaches one of these, transitively, plus the ones given.
     *
     * Nothing in this component asks it, and nothing in Symfony asks Security's either. It is
     * carried across all the same, being public API an application may have built on, and a brick
     * that has no counterpart here is a brick that cannot be deprecated there.
     *
     * @param list<string> $roles
     *
     * @return list<string>
     */
    public function getParentRoleNames(array $roles): array
    {
        $parentRoles = [];

        foreach ($roles as $role) {
            $parentRoles[$role] = $role;

            foreach ($this->map as $parent => $reachable) {
                if (isset($reachable[$role])) {
                    $parentRoles[$parent] = $parent;
                }
            }
        }

        return array_values($parentRoles);
    }

    protected function buildRoleMap(): void
    {
        $this->map = [];

        foreach (array_keys($this->hierarchy) as $main) {
            $this->map[$main] = $this->reachableFrom($main);
        }
    }

    /**
     * A hierarchy may name itself, directly or through a longer loop. Walking only what has not been
     * seen is what keeps that from spinning forever.
     *
     * @return array<string, string>
     */
    private function reachableFrom(string $role): array
    {
        $reachable = [];
        $queue = $this->hierarchy[$role];

        while ($queue) {
            $current = array_shift($queue);

            if (isset($reachable[$current])) {
                continue;
            }

            $reachable[$current] = $current;

            foreach ($this->hierarchy[$current] ?? [] as $inherited) {
                if (! isset($reachable[$inherited])) {
                    $queue[] = $inherited;
                }
            }
        }

        return $reachable;
    }
}
