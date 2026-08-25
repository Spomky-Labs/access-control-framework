<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use function in_array;
use function is_string;
use function sprintf;

/**
 * DAC: the owner holds every permission and may hand some of them over.
 */
final class OwnershipVoter implements VoterInterface
{
    public function supportsAttribute(mixed $attribute): bool
    {
        return is_string($attribute);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return $subject instanceof Document;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $identity = $this->identify($accessRequest->requester);

        if ($identity === null || ! $accessRequest->subject instanceof Document) {
            return AccessOutcome::abstain('The request carries no identity or no document.');
        }

        $document = $accessRequest->subject;

        if ($document->owner === $identity) {
            return AccessOutcome::grant(sprintf('"%s" owns "%s".', $identity, $document->name));
        }

        if (in_array($identity, $document->grants[$accessRequest->attribute] ?? [], true)) {
            return AccessOutcome::grant(sprintf('"%s" was granted "%s" on "%s" by its owner.', $identity, $accessRequest->attribute, $document->name));
        }

        return AccessOutcome::deny(sprintf('"%s" holds no "%s" permission on "%s".', $identity, $accessRequest->attribute, $document->name));
    }

    private function identify(mixed $requester): ?string
    {
        return match (true) {
            is_string($requester) => $requester,
            $requester instanceof ClearedRequester => $requester->name,
            default => null,
        };
    }
}
