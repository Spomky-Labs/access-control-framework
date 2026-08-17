<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\Bridge\Security\AuthorizationCheckerAdapter;
use AccessControl\ExpressionLanguage;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\Requester\TokenStorageRequesterProvider;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeTokenStorage;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PostVoter;
use AccessControl\Tests\Fixtures\SecurityPostVoter;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use AccessControl\Voter\Expression\ExpressionVoter;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\ExpressionLanguage as SecurityExpressionLanguage;
use Symfony\Component\Security\Core\Authorization\UserAuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter as SecurityAuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\ExpressionVoter as SecurityExpressionVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleHierarchyVoter as SecurityRoleHierarchyVoter;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Role\RoleHierarchy as SecurityRoleHierarchy;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface as SecurityRoleHierarchyInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Asks Security's AuthorizationChecker and this component's adapter the same questions, and
 * requires the same answers.
 *
 * This adapter is the seam of the migration: everything that consumes AuthorizationCheckerInterface
 * moves over without a line changed. So the parity has to hold on the contract itself, not merely
 * on the manager underneath, which SecurityParityTest already covers.
 */
final class AuthorizationCheckerParityTest extends TestCase
{
    private const HIERARCHY = ['ROLE_ADMIN' => ['ROLE_USER'], 'ROLE_SUPER_ADMIN' => ['ROLE_ADMIN']];

    public static function provideQuestions(): iterable
    {
        yield 'a role the requester holds' => ['ROLE_ADMIN', null];
        yield 'a role inherited through the hierarchy' => ['ROLE_USER', null];
        yield 'a role out of reach' => ['ROLE_SUPER_ADMIN', null];
        yield 'an authentication state' => ['IS_AUTHENTICATED', null];
        yield 'a stricter authentication state' => ['IS_AUTHENTICATED_FULLY', null];
        yield 'public access' => ['PUBLIC_ACCESS', null];
        yield 'a voter on a subject' => ['read', new Post('Hello')];
        yield 'a granting expression' => [new Expression("'ROLE_ADMIN' in role_names"), null];
        yield 'a denying expression' => [new Expression("'ROLE_SUPER_ADMIN' in role_names"), null];
        yield 'an expression delegating to the whole system' => [new Expression('is_granted("ROLE_ADMIN")'), null];
        yield 'an expression reaching into the token' => [new Expression('token.getUserIdentifier() != "nobody"'), null];
    }

    #[DataProvider('provideQuestions')]
    public function testTheSameQuestionGetsTheSameAnswer(mixed $attribute, mixed $subject)
    {
        $tokenStorage = $this->tokenStorage();

        $this->assertSame(
            $this->security($tokenStorage)->isGranted($attribute, $subject),
            $this->accessControl($tokenStorage)->isGranted($attribute, $subject),
            \sprintf('Security and AccessControl disagree on "%s".', get_debug_type($attribute).' '.var_export($attribute, true)),
        );
    }

    /**
     * Security stands a NullToken in for a missing token, so that its voters and its expressions
     * are always handed one. The adapter does the same, and the case that pins it down is the
     * expression reaching into the token: without the stand-in this component passes a null and
     * the expression fails outright, where Security answers on an empty identifier.
     *
     * Measured: removing the stand-in leaves every other question of this provider unchanged, that
     * one alone turns red. Notably PUBLIC_ACCESS does not need it, since AuthenticatedVoter grants
     * it before looking at the requester at all.
     */
    #[DataProvider('provideQuestions')]
    public function testTheSameQuestionGetsTheSameAnswerWithoutAToken(mixed $attribute, mixed $subject)
    {
        $tokenStorage = new FakeTokenStorage();

        $this->assertSame(
            $this->security($tokenStorage)->isGranted($attribute, $subject),
            $this->accessControl($tokenStorage)->isGranted($attribute, $subject),
            \sprintf('Security and AccessControl disagree on "%s" for a visitor.', get_debug_type($attribute).' '.var_export($attribute, true)),
        );
    }

    /**
     * Security: $security->isGrantedForUser($user, 'ROLE_ADMIN').
     */
    public function testCheckingForAnotherUser()
    {
        $user = new InMemoryUser('bob', null, ['ROLE_ADMIN']);

        foreach (['ROLE_ADMIN', 'ROLE_USER', 'ROLE_SUPER_ADMIN', 'PUBLIC_ACCESS'] as $attribute) {
            $this->assertSame(
                $this->security()->isGrantedForUser($user, $attribute),
                $this->accessControl()->isGrantedForUser($user, $attribute),
                \sprintf('Security and AccessControl disagree on "%s" for another user.', $attribute),
            );
        }
    }

    /**
     * The reason the user is wrapped in an offline token rather than passed bare: both stacks then
     * refuse to answer, an authentication state being meaningless outside a session. Passing the
     * user as is would have this component quietly deny where Security throws.
     */
    public function testAnAuthenticationStateIsRefusedForAnotherUserOnBothSides()
    {
        $user = new InMemoryUser('bob', null, ['ROLE_ADMIN']);

        $this->assertRefusesToAnswer(fn (): bool => $this->security()->isGrantedForUser($user, 'IS_AUTHENTICATED_FULLY'));
        $this->assertRefusesToAnswer(fn (): bool => $this->accessControl()->isGrantedForUser($user, 'IS_AUTHENTICATED_FULLY'));
    }

    /**
     * IsGrantedAttributeListener reads the decision it hands over, so leaving it untouched would
     * make getMessage() fail on an uninitialised property.
     */
    public function testTheDecisionHandedOverIsFilledIn()
    {
        $securityDecision = new AccessDecision();
        $accessControlDecision = new AccessDecision();

        $this->security()->isGranted('ROLE_SUPER_ADMIN', null, $securityDecision);
        $this->accessControl()->isGranted('ROLE_SUPER_ADMIN', null, $accessControlDecision);

        $this->assertFalse($securityDecision->isGranted);
        $this->assertFalse($accessControlDecision->isGranted);
        $this->assertStringStartsWith('Access Denied.', $securityDecision->getMessage());
        $this->assertStringStartsWith('Access Denied.', $accessControlDecision->getMessage());
        $this->assertNotEmpty($accessControlDecision->votes);
    }

    private function assertRefusesToAnswer(callable $question): void
    {
        try {
            $question();
            $this->fail('An authentication state should not be answered for an offline user.');
        } catch (InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
    }

    private function tokenStorage(): TokenStorageInterface
    {
        $tokenStorage = new FakeTokenStorage();
        $tokenStorage->setToken(new FakeToken(new FakeUser(roles: ['ROLE_ADMIN'])));

        return $tokenStorage;
    }

    /**
     * The voter list must be replayable, and its expression voter needs the checker that is built
     * from the very manager the list is given to, hence the lazy generator below.
     */
    private function security(?TokenStorageInterface $tokenStorage = null): AuthorizationChecker
    {
        $voters = new class(new SecurityRoleHierarchy(self::HIERARCHY), new AuthenticationTrustResolver()) implements \IteratorAggregate {
            public ?AuthorizationCheckerInterface $authChecker = null;

            public function __construct(
                private readonly SecurityRoleHierarchyInterface $roleHierarchy,
                private readonly AuthenticationTrustResolverInterface $trustResolver,
            ) {
            }

            public function getIterator(): \Traversable
            {
                yield new SecurityAuthenticatedVoter($this->trustResolver);
                yield new SecurityRoleHierarchyVoter($this->roleHierarchy);
                yield new SecurityExpressionVoter(new SecurityExpressionLanguage(), $this->trustResolver, $this->authChecker, $this->roleHierarchy);
                yield new SecurityPostVoter();
            }
        };

        $checker = new AuthorizationChecker($tokenStorage ?? $this->tokenStorage(), new AccessDecisionManager($voters));
        $voters->authChecker = $checker;

        return $checker;
    }

    private function accessControl(?TokenStorageInterface $tokenStorage = null): AuthorizationCheckerAdapter
    {
        $roleHierarchy = new RoleHierarchy(self::HIERARCHY);
        $trustResolver = new AuthenticationTrustResolver();
        $manager = null;

        $voters = (static function () use (&$manager, $roleHierarchy, $trustResolver) {
            yield new AuthenticatedVoter($trustResolver);
            yield new RoleVoter($roleHierarchy);
            yield new ExpressionVoter(new ExpressionLanguage(), $manager, $trustResolver, $roleHierarchy);
            yield new PostVoter();
        })();

        $manager = new AccessControlManager([new PermitOverridesStrategy()], $voters);

        return new AuthorizationCheckerAdapter($manager, new TokenStorageRequesterProvider($tokenStorage ?? $this->tokenStorage()));
    }

    /**
     * The component does not require a token storage, so the adapter serves a console command just
     * as well, which is where Security's checker cannot follow.
     */
    public function testTheAdapterWorksWithoutATokenStorage()
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new RoleVoter()]);
        $adapter = new AuthorizationCheckerAdapter($manager, new StaticRequesterProvider(new FakeToken(new FakeUser(roles: ['ROLE_ADMIN']))));

        $this->assertTrue($adapter->isGranted('ROLE_ADMIN'));
        $this->assertFalse($adapter->isGranted('ROLE_SUPER_ADMIN'));
    }

    public function testTheAdapterAnswersBothSecurityContracts()
    {
        $adapter = $this->accessControl();

        $this->assertInstanceOf(AuthorizationCheckerInterface::class, $adapter);
        $this->assertInstanceOf(UserAuthorizationCheckerInterface::class, $adapter);
    }
}
