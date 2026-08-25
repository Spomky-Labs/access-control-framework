<?php

declare(strict_types=1);

namespace AccessControl\Tests\Handler;

use AccessControl\AccessPolicyContext;
use AccessControl\Attribute\When;
use AccessControl\DecisionVote;
use AccessControl\ExpressionLanguage;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use AccessControl\Handler\WhenHandler;
use AccessControl\Test\AccessPolicyHandlerTestTrait;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use PHPUnit\Framework\TestCase;
use Symfony\Component\ExpressionLanguage\Expression;

final class WhenHandlerTest extends TestCase
{
    use AccessPolicyHandlerTestTrait;

    public static function provideSupportedPolicies(): iterable
    {
        yield [new When(new Expression('true'), [])];
    }

    /**
     * A condition that does not hold steps aside rather than refusing. Refusing would make a
     * composite meant to narrow a guard into one that closes everything it does not cover.
     */
    public function testAConditionThatDoesNotHoldStepsAside()
    {
        $outcome = $this->evaluate(new When(new Expression('false'), [self::denying()]));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
        static::assertSame('The condition (false) does not hold.', $outcome->reason);
    }

    public function testAConditionThatHoldsRequiresTheChildren()
    {
        $condition = new Expression('true');

        static::assertSame(DecisionVote::ACCESS_GRANTED, $this->evaluate(new When($condition, [self::granting()]))->decision);
        static::assertSame(DecisionVote::ACCESS_DENIED, $this->evaluate(new When($condition, [self::denying()]))->decision);
    }

    /**
     * The condition reads the circumstances the entry point handed over, which is what lets one and
     * the same composite speak about an HTTP method on the web and a console option elsewhere.
     */
    public function testTheConditionReadsTheEnvironment()
    {
        $policy = new When(new Expression('destructive'), [self::denying()]);

        static::assertSame(DecisionVote::ACCESS_DENIED, $this->evaluate($policy, new AccessPolicyContext(environment: [
            'destructive' => true,
        ]))->decision);
        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $this->evaluate($policy, new AccessPolicyContext(environment: [
            'destructive' => false,
        ]))->decision);
    }

    public function testTheConditionReadsTheRequesterAndTheArguments()
    {
        $requester = new StandaloneRequester(['ROLE_ADMIN']);

        static::assertSame(
            DecisionVote::ACCESS_GRANTED,
            $this->evaluate(
                new When(new Expression('requester.getRoles() == ["ROLE_ADMIN"] and arguments["page"] > 1'), [self::granting()]),
                new AccessPolicyContext($requester, [
                    'page' => 2,
                ]),
            )->decision,
        );
    }

    /**
     * Same tally as the other composites: an abstention neither refuses nor counts, so a condition
     * that holds over children that all step aside steps aside in turn.
     */
    public function testChildrenThatAllAbstain()
    {
        $outcome = $this->evaluate(new When(new Expression('true'), [self::abstaining()]));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
        static::assertSame('No nested access policy applied.', $outcome->reason);
    }

    public function testAConditionThatHoldsOverNothingAbstains()
    {
        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $this->evaluate(new When(new Expression('true'), []))->decision);
    }

    protected function createHandler(): AccessPolicyHandlerInterface
    {
        return new WhenHandler(new ExpressionLanguage());
    }
}
