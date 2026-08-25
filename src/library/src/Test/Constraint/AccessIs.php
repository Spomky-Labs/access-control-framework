<?php

declare(strict_types=1);

namespace AccessControl\Test\Constraint;

use AccessControl\AccessDecision;
use AccessControl\AccessOutcome;
use AccessControl\DecisionVote;
use PHPUnit\Framework\Constraint\Constraint;
use function sprintf;

/**
 * Matches the verdict of a voter or of a whole stack.
 *
 * One constraint carries the three verdicts rather than three classes carrying identical code, in
 * the manner of ResponseStatusCodeSame. Being a constraint rather than a bare comparison is what
 * puts the reason in the failure message, and it composes with LogicalNot and the others.
 */
final class AccessIs extends Constraint
{
    public function __construct(
        private readonly DecisionVote $expected,
    ) {
    }

    public function toString(): string
    {
        return match ($this->expected) {
            DecisionVote::ACCESS_GRANTED => 'is granted',
            DecisionVote::ACCESS_DENIED => 'is denied',
            DecisionVote::ACCESS_ABSTAIN => 'is left undecided',
        };
    }

    protected function matches($other): bool
    {
        return ($other instanceof AccessOutcome || $other instanceof AccessDecision) && $this->expected === $other->decision;
    }

    protected function failureDescription($other): string
    {
        return 'access ' . $this->toString();
    }

    protected function additionalFailureDescription($other): string
    {
        if (! $other instanceof AccessOutcome && ! $other instanceof AccessDecision) {
            return sprintf('Got a "%s", which is neither an access outcome nor an access decision.', get_debug_type($other));
        }

        return sprintf('Got %s.%s', $other->decision->value, $other->reason !== null ? ' Reason: ' . $other->reason : ' No reason was given.');
    }
}
