<?php

declare(strict_types=1);

namespace AccessControl\Tests\Voter\ABAC;

use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Requester\Actor;
use AccessControl\Requester\DelegatedRequesterInterface;
use AccessControl\Tests\Fixtures\DelegatedRequester;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\OfflineTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class AuthenticatedVoterTest extends TestCase
{
    public function testPublicAccessIsGrantedWithoutAnyRequester(): void
    {
        $outcome = $this->createVoter()
            ->vote(new AccessRequest(null, 'PUBLIC_ACCESS'));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    public function testPublicAccessIsGrantedToAnUnknownRequester(): void
    {
        $outcome = $this->createVoter()
            ->vote(new AccessRequest('an-api-key', 'PUBLIC_ACCESS'));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    public function testUnknownRequesterMakesTheVoterAbstain(): void
    {
        $outcome = $this->createVoter()
            ->vote(new AccessRequest('an-api-key', 'IS_AUTHENTICATED_FULLY'));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
        static::assertSame('The requester is not an instance of TokenInterface.', $outcome->reason);
    }

    public function testUnknownAttributeMakesTheVoterAbstain(): void
    {
        $outcome = $this->createVoter()
            ->vote(new AccessRequest(new FakeToken(new FakeUser()), 'ROLE_ADMIN'));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
    }

    public function testFullyAuthenticatedRequesterIsGranted(): void
    {
        $outcome = $this->createVoter()
            ->vote(new AccessRequest(new FakeToken(new FakeUser()), 'IS_AUTHENTICATED_FULLY'));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    public function testRequesterWithoutTheAuthenticationStateIsDenied(): void
    {
        $outcome = $this->createVoter()
            ->vote(new AccessRequest(new NullToken(), 'IS_AUTHENTICATED_FULLY'));

        static::assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
    }

    /**
     * PUBLIC_ACCESS is the commonest attribute of an access rule and it is decided before any trust
     * resolver is consulted, which is what lets the voter be registered in an application that has
     * no Security at all.
     */
    public function testPublicAccessIsGrantedWithoutAnyTrustResolver(): void
    {
        $outcome = new AuthenticatedVoter()
            ->vote(new AccessRequest(null, 'PUBLIC_ACCESS'));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    /**
     * Every state below PUBLIC_ACCESS is a degree of authentication, and nothing authenticates
     * without Security. Refusing rather than abstaining is what keeps that fail-closed.
     */
    public function testAnAuthenticationStateIsRefusedWithoutATrustResolver(): void
    {
        $outcome = new AuthenticatedVoter()
            ->vote(new AccessRequest(new FakeToken(new FakeUser()), 'IS_AUTHENTICATED_FULLY'));

        static::assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
        static::assertSame('No authentication trust resolver is available.', $outcome->reason);
    }

    /**
     * The delegation is read through the component's own contract rather than through Security's
     * SwitchUserToken, which is what makes IS_IMPERSONATOR decidable where there is no token at all.
     */
    public function testImpersonationIsReadThroughTheComponentContract(): void
    {
        $requester = new DelegatedRequester(new StandaloneRequester(['ROLE_ADMIN']));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $this->createVoter()->vote(new AccessRequest($requester, 'IS_IMPERSONATOR'))->decision);
    }

    public function testARequesterNobodyIsActingAsIsNotAnImpersonator(): void
    {
        $outcome = $this->createVoter()
            ->vote(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'IS_IMPERSONATOR'));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
    }

    /**
     * An offline token still raises rather than being answered, the parity with Security holding on
     * that too: an offline requester is nobody's actor, so the branch above steps aside first.
     */
    public function testAnOfflineTokenStillRaisesOnImpersonation(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->createVoter()
            ->vote(new AccessRequest(new class(['ROLE_USER']) extends AbstractToken implements OfflineTokenInterface {}, 'IS_IMPERSONATOR'));
    }

    /**
     * Security's impersonation is read where it stands, its token being none of this component's
     * business to change. Both ways of saying it meet in Actor and nowhere else, so the two stacks
     * answer alike without a line of Security having been touched.
     */
    public function testSecuritysImpersonationIsReadWhereItStands(): void
    {
        $token = new SwitchUserToken(new InMemoryUser('alice', null), 'main', ['ROLE_USER'], $original = new UsernamePasswordToken(new InMemoryUser('root', null), 'main', ['ROLE_ADMIN']));

        static::assertNotInstanceOf(DelegatedRequesterInterface::class, $token, 'Security is left untouched.');
        static::assertSame($original, Actor::of($token));
        static::assertSame(DecisionVote::ACCESS_GRANTED, $this->createVoter()->vote(new AccessRequest($token, 'IS_IMPERSONATOR'))->decision);
    }

    private function createVoter(): AuthenticatedVoter
    {
        return new AuthenticatedVoter(new AuthenticationTrustResolver());
    }
}
