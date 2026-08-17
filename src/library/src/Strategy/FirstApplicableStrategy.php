<?php

declare(strict_types=1);

namespace AccessControl\Strategy;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\CastVote;
use AccessControl\DecisionVote;

/**
 * The first voter that does not abstain settles the question.
 *
 *  - The first grant or denial met is the final decision.
 *  - If all abstain, the final decision depends on the allowIfAllAbstain property value.
 *
 * The order of the voters therefore carries the meaning here, where the other strategies are
 * order independent. Registering a voter before the others is what lets it overrule them.
 *
 * This is the "priority" strategy of the Security component.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final readonly class FirstApplicableStrategy implements StrategyInterface
{
    public function getName(): string
    {
        return 'first_applicable';
    }

    /**
     * @param iterable<CastVote> $votes
     */
    public function evaluate(AccessRequest $accessRequest, iterable $votes): AccessDecision
    {
        foreach ($votes as $vote) {
            if (DecisionVote::ACCESS_GRANTED === $vote->outcome->decision) {
                return AccessDecision::grant($accessRequest, $votes, 'The first voter that did not abstain granted access.');
            }

            if (DecisionVote::ACCESS_DENIED === $vote->outcome->decision) {
                return AccessDecision::deny($accessRequest, $votes, 'The first voter that did not abstain denied access.');
            }
        }

        return AccessDecision::abstain($accessRequest, $votes, 'All voters abstained from voting.');
    }
}
