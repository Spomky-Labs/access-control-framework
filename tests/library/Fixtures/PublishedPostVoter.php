<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

/**
 * Filters on the state of the subject rather than on its type, the way ownership,
 * ReBAC and MAC voters do.
 */
final readonly class PublishedPostVoter implements VoterInterface
{
    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        return AccessOutcome::grant('The post is published.');
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return $attribute === 'read';
    }

    public function supportsSubject(mixed $subject): bool
    {
        return $subject instanceof Post && $subject->published;
    }
}
