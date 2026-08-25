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
 * IBAC: an access control list naming individuals, with no group nor role in between.
 */
final readonly class IdentityVoter implements VoterInterface
{
    /**
     * @param array<string, list<string>> $identities Allowed identities, indexed by attribute
     */
    public function __construct(
        private array $identities,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return is_string($attribute) && isset($this->identities[$attribute]);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! is_string($accessRequest->requester)) {
            return AccessOutcome::abstain('The requester is not an identity.');
        }

        return in_array($accessRequest->requester, $this->identities[$accessRequest->attribute] ?? [], true)
            ? AccessOutcome::grant(sprintf('"%s" is listed for "%s".', $accessRequest->requester, $accessRequest->attribute))
            : AccessOutcome::deny(sprintf('"%s" is not listed for "%s".', $accessRequest->requester, $accessRequest->attribute));
    }
}
