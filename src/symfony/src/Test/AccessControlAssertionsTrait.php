<?php

declare(strict_types=1);

namespace AccessControl\Bundle\Test;

use PHPUnit\Framework\Constraint\LogicalNot;
use AccessControl\DecisionVote;
use AccessControl\Event\AccessDecisionEvents;
use AccessControl\Test\Constraint as AccessControlConstraint;
use AccessControl\VoterInterface;

/**
 * Assertions on what the access control stack decided during the last request or command.
 *
 * A refusal reaches the requester as a bare 403, on purpose. These read the decisions themselves,
 * so that a test can state which attribute was refused, and by which voter, rather than settle for
 * the status code. To assert on an answer already in hand, see the AccessOutcomeAssertionsTrait of
 * the component.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
trait AccessControlAssertionsTrait
{
    public static function assertAccessWasDeniedOn(mixed $attribute, string $message = ''): void
    {
        self::assertThat(self::getAccessDecisionEvents(), new AccessControlConstraint\AccessWasDeniedOn($attribute), $message);
    }

    public static function assertAccessWasGrantedOn(mixed $attribute, string $message = ''): void
    {
        self::assertThat(self::getAccessDecisionEvents(), new AccessControlConstraint\AccessWasDeniedOn($attribute, DecisionVote::ACCESS_GRANTED), $message);
    }

    public static function assertAccessWasNotDeniedOn(mixed $attribute, string $message = ''): void
    {
        self::assertThat(self::getAccessDecisionEvents(), new LogicalNot(new AccessControlConstraint\AccessWasDeniedOn($attribute)), $message);
    }

    /**
     * @param class-string<VoterInterface> $voter
     */
    public static function assertAccessWasDeniedBy(string $voter, string $message = ''): void
    {
        self::assertThat(self::getAccessDecisionEvents(), new AccessControlConstraint\AccessWasDeniedBy($voter), $message);
    }

    public static function assertAccessDecisionCount(int $count, string $message = ''): void
    {
        self::assertCount($count, self::getAccessDecisionEvents()->getDecisions(), $message);
    }

    public static function getAccessDecisionEvents(): AccessDecisionEvents
    {
        $container = static::getContainer();

        if ($container->has('access_control.decision_logger')) {
            return $container->get('access_control.decision_logger')->getEvents();
        }

        static::fail('A client must have AccessControl enabled in debug mode to make access assertions. Did you forget to require spomky-labs/access-control-bundle?');
    }
}
