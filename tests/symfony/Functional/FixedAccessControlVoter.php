<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

/**
 * What FixedVoter becomes once an application has moved to the component's own contract, which is
 * the second half of the migration. The same set of voters must reach the same conclusion under the
 * same combining algorithm, whichever vocabulary declares them.
 */
class FixedAccessControlVoter implements VoterInterface
{
    public function __construct(
        private readonly bool $granting,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return 'THING' === $attribute;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if ('THING' !== $accessRequest->attribute) {
            return AccessOutcome::abstain('Not the attribute this voter answers.');
        }

        return $this->granting ? AccessOutcome::grant('Always granting.') : AccessOutcome::deny('Always denying.');
    }
}
