<?php

declare(strict_types=1);

namespace AccessControl\Tests\Voter\RBAC;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class RoleVoterTest extends TestCase
{
    public function testRolesComeFromTheTokenAndNotFromTheUser(): void
    {
        $user = new InMemoryUser('bob', null, ['ROLE_USER']);
        $token = new UsernamePasswordToken($user, 'main', ['ROLE_ADMIN']);

        $outcome = (new RoleVoter())->vote(new AccessRequest($token, 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    public function testRolesCarriedByAnImpersonationTokenAreVisible(): void
    {
        $user = new InMemoryUser('bob', null, ['ROLE_USER']);
        $admin = new InMemoryUser('alice', null, ['ROLE_ADMIN']);
        $token = new SwitchUserToken($user, 'main', ['ROLE_USER', 'ROLE_PREVIOUS_ADMIN'], new UsernamePasswordToken($admin, 'main', ['ROLE_ADMIN']));

        $outcome = (new RoleVoter())->vote(new AccessRequest($token, 'ROLE_PREVIOUS_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }

    public function testTheUserIsOnlyReadWhenTheRequesterIsNotAToken(): void
    {
        $granted = (new RoleVoter())->vote(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));
        $denied = (new RoleVoter())->vote(new AccessRequest(new StandaloneRequester(['ROLE_USER']), 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $granted->decision);
        $this->assertSame(DecisionVote::ACCESS_DENIED, $denied->decision);
    }

    public function testAnUnknownRequesterHasNoRole(): void
    {
        $outcome = (new RoleVoter())->vote(new AccessRequest('an-api-key', 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_DENIED, $outcome->decision);
    }

    public function testTheHierarchyIsAppliedOnTheTokenRoles(): void
    {
        $user = new InMemoryUser('bob', null, ['ROLE_USER']);
        $token = new UsernamePasswordToken($user, 'main', ['ROLE_SUPER_ADMIN']);
        $voter = new RoleVoter(new RoleHierarchy([
            'ROLE_ADMIN' => ['ROLE_USER'],
            'ROLE_SUPER_ADMIN' => ['ROLE_ADMIN', 'ROLE_ALLOWED_TO_SWITCH'],
        ]));

        $outcome = $voter->vote(new AccessRequest($token, 'ROLE_ALLOWED_TO_SWITCH'));

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $outcome->decision);
    }
}
