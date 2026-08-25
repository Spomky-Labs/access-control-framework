<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use function in_array;

/**
 * An application voter, reached through autoconfiguration alone.
 */
final class PermissionVoter implements VoterInterface
{
    public function supportsAttribute(mixed $attribute): bool
    {
        return in_array($attribute, ['EDIT', 'DELETE'], true);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        return $accessRequest->attribute === 'EDIT'
            ? AccessOutcome::grant('Everyone may edit around here.')
            : AccessOutcome::deny('Deleting is reserved.');
    }
}
