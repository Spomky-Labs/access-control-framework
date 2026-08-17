<?php

declare(strict_types=1);

namespace AccessControl\Tests\Handler;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use AccessControl\DecisionVote;
use AccessControl\Exception\UnknownArgumentException;
use AccessControl\Handler\AccessPolicyHandler;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Test\AccessPolicyHandlerTestTrait;
use AccessControl\Tests\Fixtures\FixedOutcomeVoter;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\SubjectRecordingVoter;

/**
 * The leaf handler, the one that turns a policy into an access request. It recurses into nothing,
 * so what matters here is the translation: what the voters end up being asked.
 */
final class AccessPolicyHandlerTest extends TestCase
{
    use AccessPolicyHandlerTestTrait;

    private SubjectRecordingVoter $voter;

    public static function provideSupportedPolicies(): iterable
    {
        yield [new AccessPolicy('ROLE_ADMIN')];
        yield [new AccessPolicy(new Argument('post'))];
    }

    public function testTheVerdictOfTheManagerIsHandedBack()
    {
        $this->assertSame(DecisionVote::ACCESS_GRANTED, $this->evaluate(new AccessPolicy('EDIT'))->decision);
        $this->assertSame(DecisionVote::ACCESS_DENIED, $this->evaluate(new AccessPolicy('UNKNOWN'))->decision);
    }

    /**
     * A subject given as an Argument names a value the entry point handed over, where anything else
     * is the subject itself. Getting this backwards is what would have the voters read the string
     * "post" instead of the post.
     */
    public function testAnArgumentReferenceIsResolvedAgainstTheContext()
    {
        $post = new Post('Hello');

        $this->evaluate(new AccessPolicy('EDIT', new Argument('post')), new AccessPolicyContext(arguments: ['post' => $post]));

        $this->assertSame([$post], $this->voter->subjects);
    }

    public function testALiteralSubjectIsPassedAsIs()
    {
        $this->evaluate(new AccessPolicy('EDIT', 'post'), new AccessPolicyContext(arguments: ['post' => new Post('Hello')]));

        $this->assertSame(['post'], $this->voter->subjects);
    }

    /**
     * A map of named subjects is walked, each reference resolved in place, which is what a policy
     * naming several controller arguments relies on.
     */
    public function testAMapOfSubjectsIsWalked()
    {
        $post = new Post('Hello');

        $this->evaluate(
            new AccessPolicy('EDIT', ['post' => new Argument('post'), 'kind' => 'article']),
            new AccessPolicyContext(arguments: ['post' => $post]),
        );

        $this->assertSame([['post' => $post, 'kind' => 'article']], $this->voter->subjects);
    }

    public function testAnArgumentNobodyHandedOverIsReported()
    {
        $this->expectException(UnknownArgumentException::class);

        $this->evaluate(new AccessPolicy('EDIT', new Argument('post')));
    }

    /**
     * The environment of the policy and the one of the call are merged, the call winning: a policy
     * states what it needs, the entry point states where it is being asked.
     */
    public function testTheTwoEnvironmentsAreMerged()
    {
        $policy = new AccessPolicy('EDIT', environment: ['channel' => 'web', 'tenant' => 'acme']);

        $this->evaluate($policy, new AccessPolicyContext(environment: ['channel' => 'console']));

        $this->assertSame(['channel' => 'console', 'tenant' => 'acme'], $this->voter->environment[0]);
    }

    /**
     * The strategy named by the policy is the one the manager applies, which is how a single guard
     * can demand unanimity while the rest of the application stays on its default. Measured with a
     * grant and a denial facing each other, the only shape where the two strategies disagree.
     */
    public function testThePolicyNamesItsStrategy()
    {
        $manager = new AccessControlManager(
            [new PermitOverridesStrategy(), new DenyOverridesStrategy()],
            [
                new FixedOutcomeVoter(AccessOutcome::grant('Yes.'), ['EDIT']),
                new FixedOutcomeVoter(AccessOutcome::deny('No.'), ['EDIT']),
            ],
        );

        $evaluator = new AccessPolicyEvaluator([new AccessPolicyHandler($manager)]);

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $evaluator->evaluate(new AccessPolicy('EDIT'), new AccessPolicyContext())->decision);
        $this->assertSame(DecisionVote::ACCESS_DENIED, $evaluator->evaluate(new AccessPolicy('EDIT', strategy: 'deny_overrides'), new AccessPolicyContext())->decision);
    }

    protected function createHandler(): AccessPolicyHandlerInterface
    {
        $this->voter = new SubjectRecordingVoter('EDIT');

        return new AccessPolicyHandler(new AccessControlManager([new PermitOverridesStrategy()], [$this->voter]));
    }
}
