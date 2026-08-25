<?php

declare(strict_types=1);

namespace AccessControl\Strategy;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\CastVote;
use AccessControl\DecisionVote;

/**
 * A single denial binds the decision, whatever the other voters said.
 *
 *  - If at least one voter denies, the final decision is denied.
 *  - If all abstain, the final decision depends on the allowIfAllAbstain property value.
 *  - Otherwise, (i.e. at least one voter grants access) the final decision is granted.
 *
 * This is what the mandatory models call for, as a rule that can be overridden is not mandatory.
 *
 * This is the "unanimous" strategy of the Security component: denying as soon as one voter denies
 * and granting otherwise amounts to the unanimity of the voters that did not abstain.
 */
final readonly class DenyOverridesStrategy implements StrategyInterface
{
    public function getName(): string
    {
        return 'deny_overrides';
    }

    /**
     * @param iterable<CastVote> $votes
     */
    public function evaluate(AccessRequest $accessRequest, iterable $votes): AccessDecision
    {
        $grant = 0;

        foreach ($votes as $vote) {
            if ($vote->outcome->decision === DecisionVote::ACCESS_DENIED) {
                return AccessDecision::deny($accessRequest, $votes, 'At least one voter denied access.');
            }

            if ($vote->outcome->decision === DecisionVote::ACCESS_GRANTED) {
                ++$grant;
            }
        }

        if ($grant > 0) {
            return AccessDecision::grant($accessRequest, $votes, 'All non-abstaining voters granted access.');
        }

        return AccessDecision::abstain($accessRequest, $votes, 'All voters abstained from voting.');
    }
}
