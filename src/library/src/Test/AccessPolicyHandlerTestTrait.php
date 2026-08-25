<?php

declare(strict_types=1);

namespace AccessControl\Test;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use function assert;

/**
 * Exercises a policy handler, to be used in a PHPUnit test case.
 *
 * A handler is the extension point that was hardest to test on its own: a composite one calls the
 * evaluator back for each of its children, so a test had to assemble a manager and its voters just
 * to make a child grant or refuse, and that assembly ended up being what the test measured. Here
 * the children are FixedOutcomeAccessPolicy instances, so the test says what each child answers
 * and nothing else stands between it and the handler.
 *
 * A trait rather than a parent class, so the single inheritance slot of a test class stays free,
 * as for AccessDecisionStrategyTestTrait.
 */
trait AccessPolicyHandlerTestTrait
{
    abstract protected function createHandler(): AccessPolicyHandlerInterface;

    /**
     * The policies the handler is meant to claim.
     *
     * @return iterable<array{AccessPolicyInterface}>
     */
    abstract public static function provideSupportedPolicies(): iterable;

    #[DataProvider('provideSupportedPolicies')]
    final public function testItClaimsThePoliciesItHandles(AccessPolicyInterface $accessPolicy)
    {
        $this->assertTrue($this->createHandler()->supports($accessPolicy), $accessPolicy::class . ' should be claimed.');
    }

    /**
     * A handler that claims a policy it cannot read takes it away from the one that could: the
     * evaluator stops at the first handler that says yes.
     */
    final public function testItLeavesAForeignPolicyToAnotherHandler()
    {
        $this->assertFalse($this->createHandler()->supports(self::granting()));
    }

    final protected function evaluate(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context = new AccessPolicyContext()): AccessOutcome
    {
        return $this->createEvaluator()
            ->evaluate($accessPolicy, $context);
    }

    /**
     * The handler under test, plus the one that reads the canned children. Nothing else, so a
     * policy the handler does not claim raises rather than being quietly answered by a third party.
     */
    final protected function createEvaluator(): AccessPolicyEvaluator
    {
        return new AccessPolicyEvaluator([
            $this->createHandler(),
            new class() implements AccessPolicyHandlerInterface {
                public function supports(AccessPolicyInterface $accessPolicy): bool
                {
                    return $accessPolicy instanceof FixedOutcomeAccessPolicy;
                }

                public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
                {
                    assert($accessPolicy instanceof FixedOutcomeAccessPolicy);

                    return $accessPolicy->outcome;
                }
            },
        ]);
    }

    final protected static function granting(?string $reason = 'Granted.'): FixedOutcomeAccessPolicy
    {
        return new FixedOutcomeAccessPolicy(AccessOutcome::grant($reason));
    }

    final protected static function denying(?string $reason = 'Denied.'): FixedOutcomeAccessPolicy
    {
        return new FixedOutcomeAccessPolicy(AccessOutcome::deny($reason));
    }

    final protected static function abstaining(?string $reason = 'Abstained.'): FixedOutcomeAccessPolicy
    {
        return new FixedOutcomeAccessPolicy(AccessOutcome::abstain($reason));
    }
}
