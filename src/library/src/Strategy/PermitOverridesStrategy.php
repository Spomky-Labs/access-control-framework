<?php

declare(strict_types=1);

namespace AccessControl\Strategy;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\CastVote;
use AccessControl\DecisionVote;

/**
 * A single grant carries the decision, whatever the other voters said.
 *
 *  - If at least one voter grants access, the final decision is granted.
 *  - If all abstain, the final decision depends on the allowIfAllAbstain property value.
 *  - Otherwise, (i.e. at least one voter denies access) the final decision is denied.
 *
 * This is the "affirmative" strategy of the Security component.
 *
 * @experimental
 */
final readonly class PermitOverridesStrategy implements StrategyInterface
{
    public function getName(): string
    {
        return 'permit_overrides';
    }

    /**
     * @param iterable<CastVote> $votes
     */
    public function evaluate(AccessRequest $accessRequest, iterable $votes): AccessDecision
    {
        $deny = 0;

        foreach ($votes as $vote) {
            if ($vote->outcome->decision === DecisionVote::ACCESS_GRANTED) {
                return AccessDecision::grant($accessRequest, $votes, 'At least one voter granted access.');
            }

            if ($vote->outcome->decision === DecisionVote::ACCESS_DENIED) {
                ++$deny;
            }
        }

        if ($deny > 0) {
            return AccessDecision::deny($accessRequest, $votes, 'At least one voter denied access.');
        }

        return AccessDecision::abstain($accessRequest, $votes, 'All voters abstained from voting.');
    }
}
