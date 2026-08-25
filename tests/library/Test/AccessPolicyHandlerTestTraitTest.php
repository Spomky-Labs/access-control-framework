<?php

declare(strict_types=1);

namespace AccessControl\Tests\Test;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\DecisionVote;
use AccessControl\Exception\UnsupportedAccessPolicyException;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use AccessControl\Test\AccessPolicyHandlerTestTrait;
use AccessControl\Tests\Fixtures\Not;
use AccessControl\Tests\Fixtures\NotHandler;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

/**
 * Exercises the shipped trait the way a userland handler author would, on the Not handler of the
 * fixtures: a composite nobody ships, which is exactly the case the trait is for.
 */
final class AccessPolicyHandlerTestTraitTest extends TestCase
{
    use AccessPolicyHandlerTestTrait;

    public static function provideSupportedPolicies(): iterable
    {
        yield [new Not([self::granting()])];
    }

    public function testTheHandlerUnderTestIsReached()
    {
        static::assertSame(DecisionVote::ACCESS_DENIED, $this->evaluate(new Not([self::granting()]))->decision);
        static::assertSame(DecisionVote::ACCESS_GRANTED, $this->evaluate(new Not([self::denying()]))->decision);
    }

    /**
     * The evaluator built by the trait holds the handler under test and the canned one, and nothing
     * else: a policy the handler does not claim raises instead of being quietly answered by a third
     * party that happened to be in the list.
     */
    public function testAPolicyNobodyClaimsRaises()
    {
        $this->expectException(UnsupportedAccessPolicyException::class);

        $this->evaluate(new class() implements AccessPolicyInterface {
            public ?string $message = null;
        });
    }

    /**
     * The guard the trait forces on every handler. A handler that claims what it cannot read takes
     * the policy away from the one that could, the evaluator stopping at the first yes, so this had
     * to fail for a greedy handler rather than pass quietly.
     */
    public function testTheForeignPolicyGuardFailsOnAGreedyHandler()
    {
        $greedy = new class('greedy') extends TestCase {
            use AccessPolicyHandlerTestTrait;

            public static function provideSupportedPolicies(): iterable
            {
                yield from [];
            }

            protected function createHandler(): AccessPolicyHandlerInterface
            {
                return new class() implements AccessPolicyHandlerInterface {
                    public function supports(AccessPolicyInterface $accessPolicy): bool
                    {
                        return true;
                    }

                    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
                    {
                        return AccessOutcome::grant('Anything goes.');
                    }
                };
            }
        };

        $this->expectException(AssertionFailedError::class);

        $greedy->testItLeavesAForeignPolicyToAnotherHandler();
    }

    protected function createHandler(): AccessPolicyHandlerInterface
    {
        return new NotHandler();
    }
}
