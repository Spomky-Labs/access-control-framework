<?php

declare(strict_types=1);

namespace AccessControl\Tests\Test;

use PHPUnit\Framework\TestCase;
use AccessControl\DecisionVote;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\FirstApplicableStrategy;
use AccessControl\Strategy\MajorityStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Test\AccessDecisionStrategyTestTrait;

/**
 * Exercises the shipped trait the way a user would, and covers the four strategies as a matrix at
 * the same time. The behaviour tests of each strategy live next to it in Tests/Strategy.
 */
final class AccessDecisionStrategyTestTraitTest extends TestCase
{
    use AccessDecisionStrategyTestTrait;

    public static function provideStrategyTests(): iterable
    {
        $permitOverrides = new PermitOverridesStrategy();

        yield 'permit overrides, a single grant carries' => [$permitOverrides, self::getVoters(1, 2, 0), true];
        yield 'permit overrides, denials alone' => [$permitOverrides, self::getVoters(0, 3, 0), false];
        yield 'permit overrides, everyone abstains' => [$permitOverrides, self::getVoters(0, 0, 3), false];

        $denyOverrides = new DenyOverridesStrategy();

        yield 'deny overrides, a single denial binds' => [$denyOverrides, self::getVoters(2, 1, 0), false];
        yield 'deny overrides, grants alone' => [$denyOverrides, self::getVoters(3, 0, 0), true];
        yield 'deny overrides, abstentions are no obstacle' => [$denyOverrides, self::getVoters(1, 0, 2), true];
        yield 'deny overrides, everyone abstains' => [$denyOverrides, self::getVoters(0, 0, 3), false];

        $majority = new MajorityStrategy();

        yield 'majority, the grants weigh more' => [$majority, self::getVoters(2, 1, 0), true];
        yield 'majority, the denials weigh more' => [$majority, self::getVoters(1, 2, 0), false];
        yield 'majority, a tie grants by default' => [$majority, self::getVoters(1, 1, 0), true];
        yield 'majority, a tie can be made to deny' => [new MajorityStrategy(false), self::getVoters(1, 1, 0), false];
        yield 'majority, one heavy denial outweighs two grants' => [$majority, [self::getVoter(DecisionVote::ACCESS_DENIED, 3), ...self::getVoters(2, 0, 0)], false];

        $firstApplicable = new FirstApplicableStrategy();

        yield 'first applicable, the leading grant settles it' => [$firstApplicable, [...self::getVoters(1, 0, 0), ...self::getVoters(0, 3, 0)], true];
        yield 'first applicable, the leading denial settles it' => [$firstApplicable, [...self::getVoters(0, 1, 0), ...self::getVoters(3, 0, 0)], false];
        yield 'first applicable, abstentions are skipped' => [$firstApplicable, [...self::getVoters(0, 0, 2), ...self::getVoters(1, 0, 0)], true];
        yield 'first applicable, everyone abstains' => [$firstApplicable, self::getVoters(0, 0, 3), false];
    }
}
