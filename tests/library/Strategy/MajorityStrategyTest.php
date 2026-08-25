<?php

declare(strict_types=1);

namespace AccessControl\Tests\Strategy;

use AccessControl\AccessControlManager;
use AccessControl\AccessDecision;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Strategy\MajorityStrategy;
use AccessControl\Tests\Fixtures\FixedOutcomeVoter;
use PHPUnit\Framework\TestCase;

final class MajorityStrategyTest extends TestCase
{
    public function testAMajorityOfGrantsWins(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::grant('Granted by the first voter.')),
            new FixedOutcomeVoter(AccessOutcome::grant('Granted by the second voter.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied by the third voter.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
        static::assertSame('The grants weigh more than the denials. Granted by the first voter. Granted by the second voter.', $decision->reason);
    }

    public function testAMajorityOfDenialsWins(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::grant('Granted by the first voter.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied by the second voter.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied by the third voter.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
        static::assertSame('The denials weigh more than the grants. Denied by the second voter. Denied by the third voter.', $decision->reason);
    }

    /**
     * Security: ConsensusStrategy::$allowIfEqualGrantedDeniedDecisions, which defaults to true.
     */
    public function testATieIsGrantedByDefault(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::grant('Granted.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
        static::assertSame('Both sides weigh the same, which is configured to grant access. Granted.', $decision->reason);
    }

    public function testATieCanBeDenied(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::grant('Granted.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied.')),
        ], allowIfEqualGrantedDenied: false);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
        static::assertSame('Both sides weigh the same, which is configured to deny access. Denied.', $decision->reason);
    }

    /**
     * A tie and a general abstention are two distinct outcomes, settled by two distinct knobs:
     * the first belongs to the strategy, the second to the request.
     */
    public function testATieDoesNotFollowTheAllAbstainFlag(): void
    {
        $voters = [
            new FixedOutcomeVoter(AccessOutcome::grant('Granted.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied.')),
        ];

        static::assertSame(DecisionVote::ACCESS_GRANTED, $this->decide($voters, allowIfAllAbstain: false)->decision);
        static::assertSame(DecisionVote::ACCESS_DENIED, $this->decide($voters, allowIfAllAbstain: true, allowIfEqualGrantedDenied: false)->decision);
    }

    public function testWeightsAreTakenIntoAccount(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::deny('Denied by a heavyweight voter.', 3)),
            new FixedOutcomeVoter(AccessOutcome::grant('Granted.')),
            new FixedOutcomeVoter(AccessOutcome::grant('Granted.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
    }

    public function testAbstentionsAreNotCounted(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::grant('Granted.')),
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business.')),
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business either.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
    }

    public function testAllVotersAbstainingIsReportedAsSuch(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business.')),
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business either.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
        static::assertSame('All voters abstained from voting. Not my business. Not my business either.', $decision->reason);
    }

    public function testAllVotersAbstainingCanBeGranted(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business.')),
        ], allowIfAllAbstain: true);

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
    }

    /**
     * @param list<FixedOutcomeVoter> $voters
     */
    private function decide(array $voters, bool $allowIfAllAbstain = false, bool $allowIfEqualGrantedDenied = true): AccessDecision
    {
        $manager = new AccessControlManager([new MajorityStrategy($allowIfEqualGrantedDenied)], $voters);

        return $manager->decide(new AccessRequest(null, 'edit', allowIfAllAbstain: $allowIfAllAbstain));
    }
}
