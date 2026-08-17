<?php

declare(strict_types=1);

namespace AccessControl\Test\Constraint;

use PHPUnit\Framework\Constraint\Constraint;
use AccessControl\DecisionVote;
use AccessControl\Event\AccessDecisionEvents;
use AccessControl\Event\VoteEvent;
use AccessControl\VoterInterface;

/**
 * Matches a recorded run in which a given voter refused.
 *
 * Asserting that access was refused is rarely enough: a test that only checks the verdict passes
 * just as well when the wrong voter refuses for the wrong reason. The vote carries its voter, which
 * is why this is answered from the log rather than from the decision.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
final class AccessWasDeniedBy extends Constraint
{
    /**
     * @param class-string<VoterInterface> $voter
     */
    public function __construct(
        private readonly string $voter,
        private readonly DecisionVote $expected = DecisionVote::ACCESS_DENIED,
    ) {
    }

    public function toString(): string
    {
        return \sprintf('holds a %s cast by "%s"', $this->expected->value, $this->voter);
    }

    protected function matches($other): bool
    {
        return $other instanceof AccessDecisionEvents && [] !== $other->getVotesBy($this->voter, $this->expected);
    }

    protected function failureDescription($other): string
    {
        return 'the access control log '.$this->toString();
    }

    protected function additionalFailureDescription($other): string
    {
        if (!$other instanceof AccessDecisionEvents) {
            return \sprintf('Got a "%s" instead of a log of access decisions.', get_debug_type($other));
        }

        if (!$other->getVotes()) {
            return 'No voter was ever consulted.';
        }

        $lines = array_map(
            static fn (VoteEvent $event): string => \sprintf(
                '  %s cast %s%s',
                $event->voter::class,
                $event->voterOutcome->decision->value,
                null !== $event->voterOutcome->reason ? ': '.$event->voterOutcome->reason : '',
            ),
            $other->getVotes(),
        );

        return "The following votes were cast:\n".implode("\n", $lines);
    }
}
