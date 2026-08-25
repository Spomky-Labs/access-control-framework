<?php

declare(strict_types=1);

namespace AccessControl\Tests\Voter;

use AccessControl\AccessControlManager;
use AccessControl\AccessDecision;
use AccessControl\AccessEnvironment;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\RequesterBoundChecker;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Voter\ClosureVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use PHPUnit\Framework\TestCase;

final class ClosureVoterTest extends TestCase
{
    public function testAClosureReturningTrueGrantsAccess(): void
    {
        $decision = $this->decide(static fn (): bool => true);

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
    }

    public function testAClosureReturningFalseDeniesAccess(): void
    {
        $decision = $this->decide(static fn (): bool => false);

        static::assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
    }

    public function testTheClosureReceivesTheWholeAccessRequest(): void
    {
        $post = new Post('Hello');
        $seen = null;

        $this->decide(static function (AccessRequest $accessRequest) use (&$seen): bool {
            $seen = $accessRequest;

            return true;
        }, $post);

        static::assertSame($post, $seen->subject);
        static::assertSame('editorial', $seen->environment->get('desk'));
    }

    /**
     * The checker carries the requester of the question being answered, so a nested question never
     * depends on an ambient state, exactly as for an expression.
     */
    public function testTheClosureCanAskAFurtherQuestion(): void
    {
        $granted = $this->decide(static fn (AccessRequest $accessRequest, RequesterBoundChecker $checker): bool => $checker->isGranted('ROLE_ADMIN'));
        $denied = $this->decide(static fn (AccessRequest $accessRequest, RequesterBoundChecker $checker): bool => $checker->isGranted('ROLE_SUPER_ADMIN'));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $granted->decision);
        static::assertSame(DecisionVote::ACCESS_DENIED, $denied->decision);
    }

    public function testTheReasonNamesTheClosure(): void
    {
        $decision = $this->decide(static fn (): bool => false);

        static::assertStringContainsString('returned false', (string) $decision->reason);
    }

    public function testANonClosureAttributeIsLeftToTheOtherVoters(): void
    {
        $decision = $this->decide('ROLE_ADMIN');

        static::assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision);
        static::assertSame('At least one voter granted access. The user has the required role.', $decision->reason);
    }

    private function decide(mixed $attribute, mixed $subject = null): AccessDecision
    {
        $manager = null;

        $voters = (static function () use (&$manager) {
            yield new ClosureVoter($manager);
            yield new RoleVoter();
        })();

        $manager = new AccessControlManager([new PermitOverridesStrategy()], $voters);

        return $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), $attribute, $subject, new AccessEnvironment([
            'desk' => 'editorial',
        ])));
    }
}
