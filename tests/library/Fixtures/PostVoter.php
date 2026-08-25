<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

final class PostVoter implements VoterInterface
{
    /**
     * @var list<Post>
     */
    public array $votedOn = [];

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! $accessRequest->subject instanceof Post) {
            return AccessOutcome::abstain('The subject is not a post.');
        }

        $this->votedOn[] = $accessRequest->subject;

        return AccessOutcome::grant('The post is readable.');
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return $attribute === 'read';
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }
}
