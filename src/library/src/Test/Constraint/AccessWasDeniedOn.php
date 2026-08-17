<?php

declare(strict_types=1);

namespace AccessControl\Test\Constraint;

use PHPUnit\Framework\Constraint\Constraint;
use AccessControl\DecisionVote;
use AccessControl\Event\AccessDecisionEvent;
use AccessControl\Event\AccessDecisionEvents;

/**
 * Matches a recorded run in which a given attribute was refused.
 *
 * The counterpart of a functional test asserting a 403: the status code says the door was closed,
 * this says which door and why.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
final class AccessWasDeniedOn extends Constraint
{
    public function __construct(
        private readonly mixed $attribute,
        private readonly DecisionVote $expected = DecisionVote::ACCESS_DENIED,
    ) {
    }

    public function toString(): string
    {
        return \sprintf('%s access on "%s"', DecisionVote::ACCESS_DENIED === $this->expected ? 'denies' : 'grants', $this->describeAttribute($this->attribute));
    }

    protected function matches($other): bool
    {
        if (!$other instanceof AccessDecisionEvents) {
            return false;
        }

        foreach ($other->getDecisionsOn($this->attribute) as $event) {
            if ($this->expected === $event->accessDecision->decision) {
                return true;
            }
        }

        return false;
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

        if (!$other->getDecisions()) {
            return 'No access decision was reached at all. A controller with no access policy, or an entry point whose listener is not registered, both look like this.';
        }

        $lines = array_map(
            fn (AccessDecisionEvent $event): string => \sprintf(
                '  %s on "%s"%s',
                $event->accessDecision->decision->value,
                $this->describeAttribute($event->accessRequest->attribute),
                null !== $event->accessDecision->reason ? ': '.$event->accessDecision->reason : '',
            ),
            $other->getDecisions(),
        );

        return "The following decisions were reached:\n".implode("\n", $lines);
    }

    private function describeAttribute(mixed $attribute): string
    {
        return \is_scalar($attribute) || $attribute instanceof \Stringable ? (string) $attribute : get_debug_type($attribute);
    }
}
