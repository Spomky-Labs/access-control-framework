<?php

declare(strict_types=1);

namespace AccessControl\Voter\RBAC;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface UserWithRoleInterface
{
    /**
     * Returns the roles granted to the user.
     *
     * @return string[]
     */
    public function getRoles(): array;
}
