<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Security;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Strategy\StrategyInterface;
use Symfony\Component\Security\Core\Authorization\Strategy\AccessDecisionStrategyInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface as SecurityVoterInterface;
use function is_array;
use function sprintf;

/**
 * Lets a combining algorithm written against Security decide for this component.
 *
 * The counterpart of VoterAdapter, for the applications that named a strategy_service rather than
 * one of the four Symfony ships. Without it, installing the bundle would replace their algorithm
 * with this component's default and quietly grant what they used to refuse.
 *
 * Whether all voters abstaining ends in a grant is settled inside the adapted strategy, which is
 * where Security settles it, so the manager never sees an abstention from here.
 *
 * @experimental
 */
final readonly class StrategyAdapter implements StrategyInterface
{
    public function __construct(
        private AccessDecisionStrategyInterface $strategy,
        private string $name = 'security',
    ) {
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function evaluate(AccessRequest $accessRequest, iterable $votes): AccessDecision
    {
        $votes = is_array($votes) ? $votes : iterator_to_array($votes, false);

        $granted = $this->strategy->decide((static function () use ($votes) {
            foreach ($votes as $vote) {
                yield match ($vote->outcome->decision) {
                    DecisionVote::ACCESS_GRANTED => SecurityVoterInterface::ACCESS_GRANTED,
                    DecisionVote::ACCESS_DENIED => SecurityVoterInterface::ACCESS_DENIED,
                    default => SecurityVoterInterface::ACCESS_ABSTAIN,
                };
            }
        })());

        return $granted
            ? AccessDecision::grant($accessRequest, $votes, sprintf('"%s" granted access.', $this->strategy::class))
            : AccessDecision::deny($accessRequest, $votes, sprintf('"%s" denied access.', $this->strategy::class));
    }
}
