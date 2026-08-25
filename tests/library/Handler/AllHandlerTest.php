<?php

declare(strict_types=1);

namespace AccessControl\Tests\Handler;

use AccessControl\Attribute\All;
use AccessControl\DecisionVote;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use AccessControl\Handler\AllHandler;
use AccessControl\Test\AccessPolicyHandlerTestTrait;
use PHPUnit\Framework\TestCase;

final class AllHandlerTest extends TestCase
{
    use AccessPolicyHandlerTestTrait;

    public static function provideSupportedPolicies(): iterable
    {
        yield [new All([])];
        yield [new All([self::granting()])];
    }

    public function testEveryChildGranting()
    {
        $outcome = $this->evaluate(new All([self::granting(), self::granting()]));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    /**
     * The first denial wins and its outcome is handed back untouched, so the reason of the child
     * that refused is what the caller reads.
     */
    public function testOneChildDenyingIsEnough()
    {
        $outcome = $this->evaluate(new All([self::granting(), self::denying('The post is locked.'), self::granting()]));

        static::assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
        static::assertSame('The post is locked.', $outcome->reason);
    }

    /**
     * An abstention is not a grant: it neither refuses nor counts, so a composite made of them
     * abstains in turn rather than granting on an empty tally.
     */
    public function testChildrenThatAllAbstain()
    {
        $outcome = $this->evaluate(new All([self::abstaining(), self::abstaining()]));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
        static::assertSame('No nested access policy applied.', $outcome->reason);
    }

    public function testOneChildGrantingAmongAbstentions()
    {
        $outcome = $this->evaluate(new All([self::abstaining(), self::granting(), self::abstaining()]));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    /**
     * Nothing to require is nothing granted. Granting on an empty list would turn a composite built
     * from an empty configuration into an open door.
     */
    public function testAnEmptyCompositeAbstains()
    {
        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $this->evaluate(new All([]))->decision);
    }

    public function testCompositesNest()
    {
        $outcome = $this->evaluate(new All([self::granting(), new All([self::granting(), self::denying()])]));

        static::assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
    }

    protected function createHandler(): AccessPolicyHandlerInterface
    {
        return new AllHandler();
    }
}
