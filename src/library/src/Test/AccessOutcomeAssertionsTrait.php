<?php

declare(strict_types=1);

namespace AccessControl\Test;

use AccessControl\AccessDecision;
use AccessControl\AccessOutcome;
use AccessControl\DecisionVote;
use AccessControl\Test\Constraint\AccessIs;

/**
 * Assertions on an answer already in hand.
 *
 * Both an outcome and a decision are accepted, so the very same assertion serves a single voter
 * under test and a manager assembled from several. To assert on what an elapsed request or command
 * decided rather than on a value, see the AccessControlAssertionsTrait of FrameworkBundle.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
trait AccessOutcomeAssertionsTrait
{
    public static function assertAccessGranted(AccessOutcome|AccessDecision $answer, string $message = ''): void
    {
        static::assertThat($answer, new AccessIs(DecisionVote::ACCESS_GRANTED), $message);
    }

    public static function assertAccessDenied(AccessOutcome|AccessDecision $answer, string $message = ''): void
    {
        static::assertThat($answer, new AccessIs(DecisionVote::ACCESS_DENIED), $message);
    }

    /**
     * Note that a manager never abstains, as it settles an abstention according to the
     * allowIfAllAbstain property of the request. This is therefore about a voter that has nothing
     * to say, which is what keeps voters from getting in each other's way.
     */
    public static function assertAccessAbstained(AccessOutcome|AccessDecision $answer, string $message = ''): void
    {
        static::assertThat($answer, new AccessIs(DecisionVote::ACCESS_ABSTAIN), $message);
    }
}
