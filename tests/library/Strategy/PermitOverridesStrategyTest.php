<?php

declare(strict_types=1);

namespace AccessControl\Tests\Strategy;

use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\FakeUserWithRole;
use AccessControl\Tests\StrategyTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;

final class PermitOverridesStrategyTest extends StrategyTestCase
{
    #[DataProvider('provideScenarios')]
    public function testDecide(AccessRequest $accessRequest, DecisionVote $expectedDecision, ?string $reason): void
    {
        $accessControlManger = $this->getAccessControlManager();

        $decision = $accessControlManger->decide($accessRequest, 'permit_overrides');

        static::assertEquals($expectedDecision, $decision->decision);
        static::assertEquals($reason, $decision->reason);
    }

    /**
     * @return iterable{0: string, 1: AccessRequest, 2: DecisionVote, 3: string}
     */
    public static function provideScenarios(): iterable
    {
        yield 'permit overrides and deny on abstain' => [
            new AccessRequest(new NullToken(), 'read', 'article'),
            DecisionVote::ACCESS_DENIED,
            'All voters abstained from voting.',
        ];

        yield 'permit overrides and grant on abstain' => [
            new AccessRequest(new NullToken(), 'read', 'article', allowIfAllAbstain: true),
            DecisionVote::ACCESS_GRANTED,
            'All voters abstained from voting.',
        ];
        yield 'permit overrides and deny on unauthenticated user' => [
            new AccessRequest(new NullToken(), 'ROLE_USER'),
            DecisionVote::ACCESS_DENIED,
            'At least one voter denied access. The user does not have the required role.',
        ];

        yield 'permit overrides and grant on authenticated user (classic interface)' => [
            new AccessRequest(new FakeToken(new FakeUser()), 'ROLE_USER'),
            DecisionVote::ACCESS_GRANTED,
            'At least one voter granted access. The user has the required role.',
        ];

        yield 'permit overrides and grant on authenticated user (new interface)' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole()), 'ROLE_USER'),
            DecisionVote::ACCESS_GRANTED,
            'At least one voter granted access. The user has the required role.',
        ];

        yield 'permit overrides and grant on authenticated user (inherited role)' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole(roles: ['ROLE_SUPER_ADMIN'])), 'ROLE_ALLOWED_TO_SWITCH'),
            DecisionVote::ACCESS_GRANTED,
            'At least one voter granted access. The user has the required role.',
        ];

        yield 'permit overrides and deny on authenticated user (inherited role)' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole(roles: ['ROLE_ADMIN'])), 'ROLE_ALLOWED_TO_SWITCH'),
            DecisionVote::ACCESS_DENIED,
            'At least one voter denied access. The user does not have the required role.',
        ];

        $expression = new Expression('"ROLE_ADMIN" in role_names and is_authenticated()');
        yield 'permit overrides and grant on expression' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole(roles: ['ROLE_ADMIN'])), $expression),
            DecisionVote::ACCESS_GRANTED,
            'At least one voter granted access. Expression ("ROLE_ADMIN" in role_names and is_authenticated()) is true.',
        ];

        $expression = new Expression('"ROLE_SUPER_ADMIN" in role_names and is_fully_authenticated()');
        yield 'permit overrides and denied on expression' => [
            new AccessRequest(new FakeToken(new FakeUserWithRole(roles: ['ROLE_ADMIN'])), $expression),
            DecisionVote::ACCESS_DENIED,
            'At least one voter denied access. Expression ("ROLE_SUPER_ADMIN" in role_names and is_fully_authenticated()) is false.',
        ];
    }
}
