<?php

declare(strict_types=1);

namespace AccessControl\Tests\Voter\Expression;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessEnvironment;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\ExpressionLanguage;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\DelegatedRequester;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Tests\Fixtures\SubjectRecordingVoter;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use AccessControl\Voter\Expression\ExpressionVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\ExpressionLanguage\SyntaxError;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;

final class ExpressionVoterTest extends TestCase
{
    public function testAStringAttributeIsNeverEvaluatedAsAnExpression(): void
    {
        $outcome = $this->createVoter()->vote(new AccessRequest(new FakeToken(new FakeUser()), 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
        $this->assertSame('The attribute is not an expression.', $outcome->reason);
    }

    public function testTheFailingExpressionIsReported(): void
    {
        $expression = new Expression('"ROLE_SUPER_ADMIN" in role_names');

        $outcome = $this->createVoter()->vote(new AccessRequest(new FakeToken(new FakeUser()), $expression));

        $this->assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
        $this->assertSame('Expression ("ROLE_SUPER_ADMIN" in role_names) is false.', $outcome->reason);
    }

    public function testTheSatisfiedExpressionIsReported(): void
    {
        $expression = new Expression('"ROLE_USER" in role_names and is_authenticated()');

        $outcome = $this->createVoter()->vote(new AccessRequest(new FakeToken(new FakeUser()), $expression));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
        $this->assertSame('Expression ("ROLE_USER" in role_names and is_authenticated()) is true.', $outcome->reason);
    }

    public function testARequesterThatIsNotATokenLeavesTheTokenVariableNull(): void
    {
        $expression = new Expression('token === null and not is_authenticated()');

        $outcome = $this->createVoter()->vote(new AccessRequest('an-api-key', $expression));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    public function testANestedQuestionInheritsTheEnvironmentOfTheEnclosingOne(): void
    {
        $nested = new SubjectRecordingVoter('nested');
        $voter = $this->createVoter($nested);
        $expression = new Expression('is_granted("nested")');

        $voter->vote(new AccessRequest(new FakeToken(new FakeUser()), $expression, null, new AccessEnvironment(['request' => 'the enclosing one'])));

        $this->assertSame([['request' => 'the enclosing one']], $nested->environment);
    }

    /**
     * The actor is published only when somebody else is really asking, which is what makes "an
     * administrator, even while impersonating" expressible without typing on a Security token.
     */
    public function testTheActorIsReachableFromAnExpression(): void
    {
        $requester = new DelegatedRequester(new StandaloneRequester(['ROLE_ADMIN']), ['ROLE_USER']);
        $expression = new Expression('"ROLE_ADMIN" in actor.getRoles()');

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $this->createVoter()->vote(new AccessRequest($requester, $expression))->decision);
    }

    /**
     * Naming it on a requester nobody is acting as raises at compile time rather than reading as
     * null: a guard written for impersonation must not quietly answer something on an ordinary
     * request. The expression language refuses an unknown variable, which is exactly right here.
     */
    public function testTheActorIsAbsentWhenNobodyIsActing(): void
    {
        $this->expectException(SyntaxError::class);
        $this->expectExceptionMessage('Variable "actor" is not valid');

        $this->createVoter()->vote(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), new Expression('actor is not null')));
    }

    private function createVoter(?SubjectRecordingVoter $nestedVoter = null): ExpressionVoter
    {
        $manager = null;
        $trustResolver = new AuthenticationTrustResolver();

        $voters = (static function () use (&$manager, &$voter, $trustResolver, $nestedVoter) {
            yield $voter;
            yield new RoleVoter();
            yield new AuthenticatedVoter($trustResolver);

            if (null !== $nestedVoter) {
                yield $nestedVoter;
            }
        })();

        $manager = new AccessControlManager([new PermitOverridesStrategy()], $voters);

        return $voter = new ExpressionVoter(new ExpressionLanguage(), $manager, $trustResolver);
    }
}
