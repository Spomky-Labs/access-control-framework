<?php

declare(strict_types=1);

namespace AccessControl\Tests\Handler;

use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\DecisionVote;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use AccessControl\Handler\AtLeastOneOfHandler;
use AccessControl\Test\AccessPolicyHandlerTestTrait;
use PHPUnit\Framework\TestCase;

final class AtLeastOneOfHandlerTest extends TestCase
{
    use AccessPolicyHandlerTestTrait;

    public static function provideSupportedPolicies(): iterable
    {
        yield [new AtLeastOneOf([])];
        yield [new AtLeastOneOf([self::granting()])];
    }

    /**
     * The first grant wins, and the children after it are never asked. This is what a rule naming
     * several roles relies on, and what keeps a costly voter out of the way once a cheap one has
     * already said yes.
     */
    public function testTheFirstGrantWins()
    {
        $outcome = $this->evaluate(new AtLeastOneOf([self::denying(), self::granting('The user is an editor.'), self::denying()]));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
        static::assertSame('The user is an editor.', $outcome->reason);
    }

    /**
     * The first denial is what the caller reads back, not the last: the reason of the branch that
     * came closest to applying is the useful one.
     */
    public function testEveryChildDenying()
    {
        $outcome = $this->evaluate(new AtLeastOneOf([self::denying('Not an editor.'), self::denying('Not an admin.')]));

        static::assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
        static::assertSame('Not an editor.', $outcome->reason);
    }

    public function testADenialSurvivesLaterAbstentions()
    {
        $outcome = $this->evaluate(new AtLeastOneOf([self::abstaining(), self::denying('Not an admin.'), self::abstaining()]));

        static::assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
        static::assertSame('Not an admin.', $outcome->reason);
    }

    public function testChildrenThatAllAbstain()
    {
        $outcome = $this->evaluate(new AtLeastOneOf([self::abstaining(), self::abstaining()]));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
        static::assertSame('No nested access policy applied.', $outcome->reason);
    }

    public function testAnEmptyCompositeAbstains()
    {
        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $this->evaluate(new AtLeastOneOf([]))->decision);
    }

    public function testCompositesNest()
    {
        $outcome = $this->evaluate(new AtLeastOneOf([self::denying(), new AtLeastOneOf([self::denying(), self::granting()])]));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    protected function createHandler(): AccessPolicyHandlerInterface
    {
        return new AtLeastOneOfHandler();
    }
}
