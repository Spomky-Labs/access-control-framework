<?php

declare(strict_types=1);

namespace AccessControl\Test;

use AccessControl\AccessControlManager;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\CastVote;
use AccessControl\DecisionVote;
use AccessControl\Strategy\StrategyInterface;
use AccessControl\VoterInterface;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Runs a strategy through a matrix of votes, to be used in a PHPUnit test case.
 *
 * The counterpart of Security's AccessDecisionStrategyTestCase, deliberately down to the shape of
 * provideStrategyTests() and of the two helpers, so that an existing strategy test migrates by
 * changing the classes it names and nothing else.
 *
 * A trait rather than a parent class, so that the single inheritance slot of a test class stays
 * free. A strategy test usually has a base case of its own already, and would otherwise have to
 * choose between the two.
 *
 * The expectation is a boolean, as it is there: a manager settles an abstention rather than
 * returning it. A strategy whose abstention has to be told apart from a denial is tested by
 * calling evaluate() directly.
 */
trait AccessDecisionStrategyTestTrait
{
    /**
     * @param list<VoterInterface> $voters
     */
    #[DataProvider('provideStrategyTests')]
    final public function testDecide(StrategyInterface $strategy, array $voters, bool $expected)
    {
        $manager = new AccessControlManager([$strategy], $voters);
        $decision = $manager->decide(new AccessRequest(null, 'ROLE_FOO'));

        $this->assertSame($expected, $decision->decision === DecisionVote::ACCESS_GRANTED, $decision->reason ?? '');
    }

    /**
     * @return iterable<array{StrategyInterface, list<VoterInterface>, bool}>
     */
    abstract public static function provideStrategyTests(): iterable;

    /**
     * @return list<VoterInterface>
     */
    final protected static function getVoters(int $grants, int $denies, int $abstains): array
    {
        $voters = [];

        for ($i = 0; $i < $grants; ++$i) {
            $voters[] = static::getVoter(DecisionVote::ACCESS_GRANTED);
        }
        for ($i = 0; $i < $denies; ++$i) {
            $voters[] = static::getVoter(DecisionVote::ACCESS_DENIED);
        }
        for ($i = 0; $i < $abstains; ++$i) {
            $voters[] = static::getVoter(DecisionVote::ACCESS_ABSTAIN);
        }

        return $voters;
    }

    /**
     * A vote to hand to evaluate() directly, for the strategies whose abstention has to be told
     * apart from a denial. A strategy never looks at who voted, so the voter is a stand in.
     */
    final protected static function getCastVote(DecisionVote $vote, ?string $reason = null, int|float $weight = 1): CastVote
    {
        return new CastVote(static::getVoter($vote, $weight), new AccessOutcome($vote, $reason, $weight));
    }

    final protected static function getVoter(DecisionVote $vote, int|float $weight = 1): VoterInterface
    {
        return new readonly class($vote, $weight) implements VoterInterface {
            public function __construct(
                private DecisionVote $vote,
                private int|float $weight,
            ) {
            }

            public function vote(AccessRequest $accessRequest): AccessOutcome
            {
                return new AccessOutcome($this->vote, null, $this->weight);
            }

            public function supportsAttribute(mixed $attribute): bool
            {
                return true;
            }

            public function supportsSubject(mixed $subject): bool
            {
                return true;
            }
        };
    }
}
