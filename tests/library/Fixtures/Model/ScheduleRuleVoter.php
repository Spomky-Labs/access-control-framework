<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use Symfony\Component\Clock\ClockInterface;
use function sprintf;

/**
 * RuBAC: a system wide rule, which no permission held elsewhere may override.
 *
 * The rule reads the clock itself rather than a piece of environment an entry point may forget to
 * fill in, abstains when it does not apply, and its denial binds the whole decision under a
 * strategy that lets denials win.
 */
final readonly class ScheduleRuleVoter implements VoterInterface
{
    public function __construct(
        private ClockInterface $clock,
        private int $opensAt = 9,
        private int $closesAt = 18,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return true;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $hour = (int) $this->clock->now()
            ->format('G');

        if ($hour < $this->opensAt || $hour >= $this->closesAt) {
            return AccessOutcome::deny(sprintf('%dh is outside the %dh to %dh window.', $hour, $this->opensAt, $this->closesAt));
        }

        return AccessOutcome::abstain(sprintf('%dh is inside the opening hours.', $hour));
    }
}
