<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use function sprintf;

/**
 * MAC and LBAC: the system, not the owner, rules over the labels the requester and the resource carry.
 *
 * Bell-LaPadula: no read up, no write down.
 */
final class MandatoryAccessVoter implements VoterInterface
{
    public function supportsAttribute(mixed $attribute): bool
    {
        return $attribute === 'read' || $attribute === 'write';
    }

    public function supportsSubject(mixed $subject): bool
    {
        return $subject instanceof Document;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! $accessRequest->requester instanceof ClearedRequester || ! $accessRequest->subject instanceof Document) {
            return AccessOutcome::abstain('The request carries no security label.');
        }

        $clearance = $accessRequest->requester->clearance;
        $classification = $accessRequest->subject->classification;

        if ($accessRequest->attribute === 'read') {
            return $clearance->dominates($classification)
                ? AccessOutcome::grant(sprintf('Clearance %s dominates classification %s.', $clearance, $classification))
                : AccessOutcome::deny(sprintf('Clearance %s does not dominate classification %s.', $clearance, $classification));
        }

        return $classification->dominates($clearance)
            ? AccessOutcome::grant(sprintf('Classification %s dominates clearance %s.', $classification, $clearance))
            : AccessOutcome::deny(sprintf('Writing down from clearance %s to classification %s is forbidden.', $clearance, $classification));
    }
}
