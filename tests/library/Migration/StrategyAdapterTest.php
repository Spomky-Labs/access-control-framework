<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\Bridge\Security\StrategyAdapter;
use AccessControl\CastVote;
use AccessControl\DecisionVote;
use AccessControl\Tests\Fixtures\FixedOutcomeVoter;
use Symfony\Component\Security\Core\Authorization\AccessDecision as SecurityAccessDecision;
use Symfony\Component\Security\Core\Authorization\Strategy\AccessDecisionStrategyInterface;
use Symfony\Component\Security\Core\Authorization\Strategy\AffirmativeStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\ConsensusStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\PriorityStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\UnanimousStrategy;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface as SecurityVoterInterface;

/**
 * An application may have named a combining algorithm of its own, which the bridge wraps rather
 * than replaces, exactly as it wraps the voters. Without this, installing the bundle would silently
 * put the component's own default in its place.
 */
final class StrategyAdapterTest extends TestCase
{
    /**
     * @return iterable<string, array{0: AccessDecisionStrategyInterface, 1: bool}>
     */
    public static function provideStrategies(): iterable
    {
        yield 'affirmative, one grant is enough' => [new AffirmativeStrategy(), true];
        yield 'unanimous, one denial is enough' => [new UnanimousStrategy(), false];
        yield 'consensus, the denials weigh more' => [new ConsensusStrategy(), false];
        yield 'priority, the first to speak decides' => [new PriorityStrategy(), false];
    }

    /**
     * Two refusing against one granting, the shape that separates the four algorithms Symfony
     * ships. Voters that agree say nothing about the algorithm combining them.
     */
    #[DataProvider('provideStrategies')]
    public function testTheFourAlgorithmsOfSecurityAnswerThroughTheAdapter(AccessDecisionStrategyInterface $strategy, bool $granted)
    {
        $decision = (new StrategyAdapter($strategy))->evaluate(new AccessRequest(null, 'THING'), [
            self::cast(AccessOutcome::deny('no')),
            self::cast(AccessOutcome::deny('no')),
            self::cast(AccessOutcome::grant('yes')),
        ]);

        $this->assertSame($granted ? DecisionVote::ACCESS_GRANTED : DecisionVote::ACCESS_DENIED, $decision->decision);
    }

    public function testAnAbstentionIsSaidInSecurityTerms()
    {
        $seen = [];
        $strategy = new class($seen) implements AccessDecisionStrategyInterface {
            public function __construct(private array &$seen)
            {
            }

            public function decide(\Traversable $results, ?SecurityAccessDecision $accessDecision = null): bool
            {
                $this->seen = iterator_to_array($results, false);

                return true;
            }
        };

        (new StrategyAdapter($strategy))->evaluate(new AccessRequest(null, 'THING'), [
            self::cast(AccessOutcome::grant('yes')),
            self::cast(AccessOutcome::abstain('nothing to say')),
            self::cast(AccessOutcome::deny('no')),
        ]);

        $this->assertSame([
            SecurityVoterInterface::ACCESS_GRANTED,
            SecurityVoterInterface::ACCESS_ABSTAIN,
            SecurityVoterInterface::ACCESS_DENIED,
        ], $seen);
    }

    /**
     * The manager keys its algorithms by name and refuses two under the same one, so the adapter
     * carries the name the bridge registers it under.
     */
    private static function cast(AccessOutcome $outcome): CastVote
    {
        return new CastVote(new FixedOutcomeVoter($outcome), $outcome);
    }

    public function testItCarriesTheNameItIsRegisteredUnder()
    {
        $this->assertSame('security', (new StrategyAdapter(new AffirmativeStrategy()))->getName());
        $this->assertSame('the_application', (new StrategyAdapter(new AffirmativeStrategy(), 'the_application'))->getName());
    }

    /**
     * Whether an all abstaining vote ends in a grant is settled inside the adapted strategy, which
     * is where Security settles it, so the manager never sees an abstention coming from here.
     */
    public function testWhetherAllAbstainingGrantsIsLeftToTheAdaptedStrategy()
    {
        $votes = [self::cast(AccessOutcome::abstain('nothing to say'))];

        $this->assertSame(DecisionVote::ACCESS_DENIED, (new StrategyAdapter(new AffirmativeStrategy(false)))->evaluate(new AccessRequest(null, 'THING'), $votes)->decision);
        $this->assertSame(DecisionVote::ACCESS_GRANTED, (new StrategyAdapter(new AffirmativeStrategy(true)))->evaluate(new AccessRequest(null, 'THING'), $votes)->decision);
    }
}
