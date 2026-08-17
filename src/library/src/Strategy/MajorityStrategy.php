<?php

declare(strict_types=1);

namespace AccessControl\Strategy;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\CastVote;
use AccessControl\DecisionVote;

/**
 * The heavier side wins: the weights of the grants are summed against those of the denials.
 *
 *  - The greater sum carries the decision, abstentions being left out.
 *  - If both sides weigh the same and at least one voter expressed itself, the decision depends
 *    on the allowIfEqualGrantedDenied property value.
 *  - If all abstain, the final decision depends on the allowIfAllAbstain property value.
 *
 * Unlike the three other strategies, this one reads the weight an outcome carries, so a voter may
 * be given more say than the others without being given a veto.
 *
 * This is the "consensus" strategy of the Security component, which counts votes rather than
 * weighing them. XACML defines no such combining algorithm.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final readonly class MajorityStrategy implements StrategyInterface
{
    public function __construct(
        private bool $allowIfEqualGrantedDenied = true,
    ) {
    }

    public function getName(): string
    {
        return 'majority';
    }

    /**
     * @param iterable<CastVote> $votes
     */
    public function evaluate(AccessRequest $accessRequest, iterable $votes): AccessDecision
    {
        $grantWeight = 0;
        $denyWeight = 0;
        $expressed = 0;

        foreach ($votes as $vote) {
            if (DecisionVote::ACCESS_GRANTED === $vote->outcome->decision) {
                $grantWeight += $vote->outcome->weight;
                ++$expressed;
            } elseif (DecisionVote::ACCESS_DENIED === $vote->outcome->decision) {
                $denyWeight += $vote->outcome->weight;
                ++$expressed;
            }
        }

        if ($denyWeight > $grantWeight) {
            return AccessDecision::deny($accessRequest, $votes, 'The denials weigh more than the grants.');
        }

        if ($grantWeight > $denyWeight) {
            return AccessDecision::grant($accessRequest, $votes, 'The grants weigh more than the denials.');
        }

        if (0 === $expressed) {
            return AccessDecision::abstain($accessRequest, $votes, 'All voters abstained from voting.');
        }

        return $this->allowIfEqualGrantedDenied
            ? AccessDecision::grant($accessRequest, $votes, 'Both sides weigh the same, which is configured to grant access.')
            : AccessDecision::deny($accessRequest, $votes, 'Both sides weigh the same, which is configured to deny access.');
    }
}
