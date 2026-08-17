<?php

declare(strict_types=1);

namespace AccessControl\Tests;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Exception\InvalidStrategyException;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\FixedOutcomeVoter;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PublishedPostVoter;
use AccessControl\Tests\Fixtures\RecordingVoter;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Tests\Fixtures\ThrowingVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;

final class AccessControlManagerTest extends TestCase
{
    public function testSupportCacheDoesNotLeakAcrossAttributeValues(): void
    {
        $voter = new RecordingVoter(['ROLE_ADMIN']);
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [$voter]);

        $manager->decide(new AccessRequest(new NullToken(), 'PUBLIC_ACCESS'));
        $decision = $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
        $this->assertSame(['ROLE_ADMIN'], $voter->voteCalls);
    }

    public function testSupportsAttributeIsCalledOncePerAttributeValue(): void
    {
        $voter = new RecordingVoter(['ROLE_ADMIN']);
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [$voter]);

        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));
        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));
        $manager->decide(new AccessRequest(new NullToken(), 'PUBLIC_ACCESS'));

        $this->assertSame(['ROLE_ADMIN', 'PUBLIC_ACCESS'], $voter->supportsAttributeCalls);
    }

    public function testResetDropsTheAttributeCache(): void
    {
        $voter = new RecordingVoter(['ROLE_ADMIN']);
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [$voter]);

        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));
        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));
        $manager->reset();
        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));

        $this->assertSame(['ROLE_ADMIN', 'ROLE_ADMIN'], $voter->supportsAttributeCalls);
    }

    public function testResetKeepsTheVotersOfANonRewindableIterable(): void
    {
        $voter = new RecordingVoter(['ROLE_ADMIN']);
        $voters = (static function () use ($voter) {
            yield $voter;
        })();

        $manager = new AccessControlManager([new PermitOverridesStrategy()], $voters);

        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));
        $manager->reset();
        $decision = $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
    }

    public function testSupportsSubjectIsNeverCached(): void
    {
        $voter = new RecordingVoter(['ROLE_ADMIN']);
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [$voter]);

        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN', new \stdClass()));
        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN', new \stdClass()));
        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));

        $this->assertSame([\stdClass::class, \stdClass::class, 'null'], $voter->supportsSubjectCalls);
    }

    public function testTwoSubjectsOfTheSameTypeAreJudgedOnTheirOwnState(): void
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new PublishedPostVoter()]);

        $granted = $manager->decide(new AccessRequest(null, 'read', new Post('Published', true)));
        $denied = $manager->decide(new AccessRequest(null, 'read', new Post('Draft', false)));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $granted->decision);
        $this->assertSame(DecisionVote::ACCESS_DENIED, $denied->decision);
    }

    public function testSupportsAttributeIsNotCachedForNonStringAttributes(): void
    {
        $voter = new RecordingVoter([]);
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [$voter]);

        $manager->decide(new AccessRequest(new NullToken(), new \stdClass()));
        $manager->decide(new AccessRequest(new NullToken(), new \stdClass()));

        $this->assertCount(2, $voter->supportsAttributeCalls);
    }

    public function testUnsupportedSubjectTypeSkipsTheVoter(): void
    {
        $voter = new RecordingVoter(['ROLE_ADMIN'], [\stdClass::class]);
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [$voter]);

        $decision = $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN', 'a string subject'));

        $this->assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
        $this->assertSame([], $voter->voteCalls);
    }

    public function testVotersCanBeGivenAsANonRewindableIterable(): void
    {
        $voter = new RecordingVoter(['ROLE_ADMIN']);
        $voters = (static function () use ($voter) {
            yield $voter;
        })();

        $manager = new AccessControlManager([new PermitOverridesStrategy()], $voters);

        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));
        $decision = $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
        $this->assertCount(2, $voter->voteCalls);
    }

    public function testRequesterDoesNotHaveToBeASecurityToken(): void
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new RoleVoter()]);

        $granted = $manager->decide(new AccessRequest(new StandaloneRequester(), 'ROLE_ADMIN'));
        $denied = $manager->decide(new AccessRequest(new StandaloneRequester(), 'ROLE_SUPER_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $granted->decision);
        $this->assertSame('At least one voter granted access. The user has the required role.', $granted->reason);
        $this->assertSame(DecisionVote::ACCESS_DENIED, $denied->decision);
    }

    public function testRequesterCanBeAnythingWhenNoVoterUnderstandsIt(): void
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new RoleVoter()]);

        $decision = $manager->decide(new AccessRequest('an-api-key', 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
    }

    /**
     * A voter that cannot reach its source of truth has no opinion to give, which is not the same
     * as having nothing to say. XACML tells the two apart as Indeterminate and NotApplicable; here
     * the exception simply travels, so the entry point fails closed instead of granting on the
     * strength of the voters that did answer.
     */
    public function testAFailingVoterDoesNotSilentlyBecomeAnAbstention(): void
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [
            new ThrowingVoter(),
            new FixedOutcomeVoter(AccessOutcome::grant('Granted.')),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The relationship store is unreachable.');

        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'));
    }

    public function testUnknownStrategyIsRejected(): void
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], []);

        $this->expectException(InvalidStrategyException::class);

        $manager->decide(new AccessRequest(new NullToken(), 'ROLE_ADMIN'), 'nope');
    }

    public function testTwoStrategiesCannotShareTheSameName(): void
    {
        $this->expectException(InvalidStrategyException::class);
        $this->expectExceptionMessage('Strategy "permit_overrides" is registered twice');

        new AccessControlManager([new PermitOverridesStrategy(), new PermitOverridesStrategy()], []);
    }

    public function testUnknownDefaultStrategyIsRejectedAtConstruction(): void
    {
        $this->expectException(InvalidStrategyException::class);
        $this->expectExceptionMessage('The default strategy "nope" is not registered.');

        new AccessControlManager([new PermitOverridesStrategy()], [], 'nope');
    }

    public function testTheFirstStrategyIsTheDefaultOne(): void
    {
        $manager = new AccessControlManager([new DenyOverridesStrategy(), new PermitOverridesStrategy()], [new RoleVoter()]);

        $decision = $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));

        $this->assertSame('All non-abstaining voters granted access. The user has the required role.', $decision->reason);
    }

    public function testAnEmptyStrategyListFallsBackToAffirmative(): void
    {
        $manager = new AccessControlManager([], [new RoleVoter()]);

        $decision = $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
        $this->assertSame('At least one voter granted access. The user has the required role.', $decision->reason);
    }
}
