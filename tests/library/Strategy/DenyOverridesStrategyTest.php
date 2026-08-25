<?php

declare(strict_types=1);

namespace AccessControl\Tests\Strategy;

use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeUserWithRole;
use AccessControl\Tests\StrategyTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class DenyOverridesStrategyTest extends StrategyTestCase
{
    #[DataProvider('provideScenarios')]
    public function testDecide(AccessRequest $accessRequest, DecisionVote $expectedDecision, ?string $reason): void
    {
        $accessControlManger = $this->getAccessControlManager();

        $decision = $accessControlManger->decide($accessRequest, 'deny_overrides');

        static::assertEquals($expectedDecision, $decision->decision);
        static::assertEquals($reason, $decision->reason);
    }

    /**
     * @return iterable{0: string, 1: AccessRequest, 2: DecisionVote, 3: string}
     */
    public static function provideScenarios(): iterable
    {
        yield 'deny overrides and deny on a role the user does not reach' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole(roles: ['ROLE_ADMIN'])), 'ROLE_SUPER_ADMIN'),
            DecisionVote::ACCESS_DENIED,
            'At least one voter denied access. The user does not have the required role.',
        ];

        yield 'deny overrides and grant on a directly held role' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole(roles: ['ROLE_ADMIN'])), 'ROLE_ADMIN'),
            DecisionVote::ACCESS_GRANTED,
            'All non-abstaining voters granted access. The user has the required role.',
        ];

        yield 'deny overrides and grant on an inherited role' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole(roles: ['ROLE_SUPER_ADMIN'])), 'ROLE_ALLOWED_TO_SWITCH'),
            DecisionVote::ACCESS_GRANTED,
            'All non-abstaining voters granted access. The user has the required role.',
        ];
    }
}
