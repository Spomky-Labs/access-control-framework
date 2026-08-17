<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

/**
 * ABAC: the three sources of attributes are the requester, the resource and the environment.
 *
 * The requester and the resource are plain maps, which the mixed types of the access request allow,
 * and the environment travels in the environment bag the entry points fill in.
 */
final class AttributeBasedVoter implements VoterInterface
{
    public function supportsAttribute(mixed $attribute): bool
    {
        return 'read' === $attribute;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (!\is_array($accessRequest->requester) || !\is_array($accessRequest->subject)) {
            return AccessOutcome::abstain('The request carries no attributes.');
        }

        if (($accessRequest->requester['department'] ?? null) !== ($accessRequest->subject['department'] ?? null)) {
            return AccessOutcome::deny('The requester and the resource belong to different departments.');
        }

        if ('corporate' !== $accessRequest->environment->get('network')) {
            return AccessOutcome::deny('The request does not come from the corporate network.');
        }

        return AccessOutcome::grant('Same department, on the corporate network.');
    }
}
