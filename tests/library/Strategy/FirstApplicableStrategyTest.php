<?php

declare(strict_types=1);

namespace AccessControl\Tests\Strategy;

use AccessControl\AccessControlManager;
use AccessControl\AccessDecision;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Strategy\FirstApplicableStrategy;
use AccessControl\Tests\Fixtures\FixedOutcomeVoter;
use PHPUnit\Framework\TestCase;

final class FirstApplicableStrategyTest extends TestCase
{
    public function testTheFirstGrantSettlesTheQuestion(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::grant('Granted by the first voter.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied by the second voter.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
        static::assertSame('The first voter that did not abstain granted access. Granted by the first voter.', $decision->reason);
    }

    public function testTheFirstDenialSettlesTheQuestion(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::deny('Denied by the first voter.')),
            new FixedOutcomeVoter(AccessOutcome::grant('Granted by the second voter.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
        static::assertSame('The first voter that did not abstain denied access. Denied by the first voter.', $decision->reason);
    }

    /**
     * This is the property that sets this strategy apart from the three others, which are all
     * order independent: registering a voter first is what lets it overrule the rest.
     */
    public function testTheOrderOfTheVotersCarriesTheMeaning(): void
    {
        $grant = new FixedOutcomeVoter(AccessOutcome::grant('Granted.'));
        $deny = new FixedOutcomeVoter(AccessOutcome::deny('Denied.'));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $this->decide([$grant, $deny])->decision);
        static::assertSame(DecisionVote::ACCESS_DENIED, $this->decide([$deny, $grant])->decision);
    }

    public function testAbstentionsAreSkipped(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business.')),
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business either.')),
            new FixedOutcomeVoter(AccessOutcome::deny('Denied by the third voter.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
    }

    public function testAllVotersAbstainingIsReportedAsSuch(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business.')),
        ]);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
        static::assertSame('All voters abstained from voting. Not my business.', $decision->reason);
    }

    public function testAllVotersAbstainingCanBeGranted(): void
    {
        $decision = $this->decide([
            new FixedOutcomeVoter(AccessOutcome::abstain('Not my business.')),
        ], true);

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
    }

    /**
     * @param list<FixedOutcomeVoter> $voters
     */
    private function decide(array $voters, bool $allowIfAllAbstain = false): AccessDecision
    {
        $manager = new AccessControlManager([new FirstApplicableStrategy()], $voters);

        return $manager->decide(new AccessRequest(null, 'edit', allowIfAllAbstain: $allowIfAllAbstain));
    }
}
