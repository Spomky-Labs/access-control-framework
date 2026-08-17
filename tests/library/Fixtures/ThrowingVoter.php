<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

/**
 * A voter whose source of truth is unreachable, the case XACML calls Indeterminate.
 */
final class ThrowingVoter implements VoterInterface
{
    public function supportsAttribute(mixed $attribute): bool
    {
        return true;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        throw new \RuntimeException('The relationship store is unreachable.');
    }
}
