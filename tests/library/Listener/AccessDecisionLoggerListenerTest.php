<?php

declare(strict_types=1);

namespace AccessControl\Tests\Listener;

use AccessControl\AccessControlManager;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Listener\AccessDecisionLoggerListener;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Test\Constraint\AccessWasDeniedBy;
use AccessControl\Test\Constraint\AccessWasDeniedOn;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Voter\RBAC\RoleVoter;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * The recorder and the two constraints built on it, covered on their own. What they are for, an
 * integration test that has just been refused access and wants to know why and by whom, is proven
 * once the component is wired into the framework.
 */
final class AccessDecisionLoggerListenerTest extends TestCase
{
    private EventDispatcher $dispatcher;

    private AccessDecisionLoggerListener $logger;

    protected function setUp(): void
    {
        $this->dispatcher = new EventDispatcher();
        $this->logger = new AccessDecisionLoggerListener();
        $this->dispatcher->addSubscriber($this->logger);
    }

    public function testDecisionsAndVotesAreBothRecorded(): void
    {
        $this->decide('ROLE_SUPER_ADMIN');

        static::assertCount(1, $this->logger->getEvents()->getDecisions());
        static::assertCount(1, $this->logger->getEvents()->getVotes());
    }

    public function testADenialIsFoundByItsAttribute(): void
    {
        $this->decide('ROLE_SUPER_ADMIN');

        static::assertThat($this->logger->getEvents(), new AccessWasDeniedOn('ROLE_SUPER_ADMIN'));
    }

    /**
     * Asserting the verdict alone passes just as well when the wrong voter refuses for the wrong
     * reason. The vote carries its voter, so the log answers what the decision cannot.
     */
    public function testADenialIsFoundByItsVoter(): void
    {
        $this->decide('ROLE_SUPER_ADMIN');

        static::assertThat($this->logger->getEvents(), new AccessWasDeniedBy(RoleVoter::class));
    }

    public function testAGrantedRunHoldsNoDenial(): void
    {
        $this->decide('ROLE_ADMIN');

        static::assertSame([], $this->logger->getEvents()->getVotesBy(RoleVoter::class, DecisionVote::ACCESS_DENIED));
        static::assertCount(1, $this->logger->getEvents()->getVotesBy(RoleVoter::class, DecisionVote::ACCESS_GRANTED));
    }

    /**
     * A nested question produces a decision of its own, so a single call may leave several behind.
     */
    public function testEveryDecisionOfARunIsKept(): void
    {
        $this->decide('ROLE_ADMIN');
        $this->decide('ROLE_SUPER_ADMIN');

        static::assertCount(2, $this->logger->getEvents()->getDecisions());
        static::assertCount(1, $this->logger->getEvents()->getDecisionsOn('ROLE_SUPER_ADMIN'));
    }

    public function testResetEmptiesTheLog(): void
    {
        $this->decide('ROLE_ADMIN');
        $this->logger->reset();

        static::assertSame([], $this->logger->getEvents()->getDecisions());
        static::assertSame([], $this->logger->getEvents()->getVotes());
    }

    public function testTheFailureTellsWhatWasActuallyDecided(): void
    {
        $this->decide('ROLE_SUPER_ADMIN');

        try {
            static::assertThat($this->logger->getEvents(), new AccessWasDeniedOn('ROLE_EDITOR'));
            static::fail('The constraint should not have matched.');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('The following decisions were reached:', $failure->getMessage());
            static::assertStringContainsString('ACCESS_DENIED on "ROLE_SUPER_ADMIN"', $failure->getMessage());
        }
    }

    public function testTheFailureSaysWhenNothingWasDecidedAtAll(): void
    {
        try {
            static::assertThat($this->logger->getEvents(), new AccessWasDeniedOn('ROLE_ADMIN'));
            static::fail('The constraint should not have matched.');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('No access decision was reached at all.', $failure->getMessage());
        }
    }

    public function testTheFailureListsTheVotesThatWereCast(): void
    {
        $this->decide('ROLE_ADMIN');

        try {
            static::assertThat($this->logger->getEvents(), new AccessWasDeniedBy(RoleVoter::class));
            static::fail('The constraint should not have matched.');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('The following votes were cast:', $failure->getMessage());
            static::assertStringContainsString(RoleVoter::class . ' cast ACCESS_GRANTED', $failure->getMessage());
        }
    }

    private function decide(string $attribute): void
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new RoleVoter()], dispatcher: $this->dispatcher);

        $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), $attribute));
    }
}
