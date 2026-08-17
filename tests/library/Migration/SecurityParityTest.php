<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\ExpressionLanguage;
use AccessControl\RequesterBoundChecker;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\FirstApplicableStrategy;
use AccessControl\Strategy\MajorityStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PostVoter;
use AccessControl\Tests\Fixtures\SecurityPostVoter;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use AccessControl\Voter\ClosureVoter;
use AccessControl\Voter\Expression\ExpressionVoter;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\OfflineTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\ExpressionLanguage as SecurityExpressionLanguage;
use Symfony\Component\Security\Core\Authorization\Strategy\AffirmativeStrategy as SecurityAffirmativeStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\ConsensusStrategy as SecurityConsensusStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\PriorityStrategy as SecurityPriorityStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\UnanimousStrategy as SecurityUnanimousStrategy;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter as SecurityAuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\ClosureVoter as SecurityClosureVoter;
use Symfony\Component\Security\Core\Authorization\Voter\ExpressionVoter as SecurityExpressionVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleHierarchyVoter as SecurityRoleHierarchyVoter;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Role\RoleHierarchy as SecurityRoleHierarchy;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface as SecurityRoleHierarchyInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\IsGrantedContext;

/**
 * Runs the same question through Security and through this component, and asserts they answer alike.
 *
 * Each test states the Security call it stands for, so that it doubles as a migration guide. Any
 * behavioural drift between the two implementations breaks a test here rather than an application.
 */
final class SecurityParityTest extends TestCase
{
    private const HIERARCHY = [
        'ROLE_ADMIN' => ['ROLE_USER'],
        'ROLE_SUPER_ADMIN' => ['ROLE_ADMIN', 'ROLE_ALLOWED_TO_SWITCH'],
    ];

    private TokenInterface $token;

    protected function setUp(): void
    {
        $this->token = new UsernamePasswordToken(new InMemoryUser('bob', null, ['ROLE_ADMIN']), 'main', ['ROLE_ADMIN']);
    }

    /**
     * Security: $security->isGranted('ROLE_ADMIN');.
     */
    public function testCheckingARoleHeldByTheCurrentRequester(): void
    {
        $this->assertGrantedAlike('ROLE_ADMIN');
        $this->assertGrantedAlike('ROLE_SUPER_ADMIN');
    }

    /**
     * Security: $security->isGranted('ROLE_USER'); // reached through role_hierarchy.
     */
    public function testCheckingAnInheritedRole(): void
    {
        $this->assertGrantedAlike('ROLE_USER');
    }

    /**
     * Security: the token carries its own roles, taken at authentication time, which may differ
     * from the ones the user object holds now.
     */
    public function testCheckingARoleCarriedByTheTokenOnly(): void
    {
        $this->token = new UsernamePasswordToken(new InMemoryUser('bob', null, ['ROLE_USER']), 'main', ['ROLE_ADMIN']);

        $this->assertGrantedAlike('ROLE_ADMIN');
    }

    /**
     * Security: switch_user adds ROLE_PREVIOUS_ADMIN to the token, never to the user object.
     */
    public function testCheckingARoleAddedByImpersonation(): void
    {
        $impersonated = new InMemoryUser('bob', null, ['ROLE_USER']);
        $impersonator = new UsernamePasswordToken(new InMemoryUser('alice', null, ['ROLE_ADMIN']), 'main', ['ROLE_ADMIN']);

        $this->token = new SwitchUserToken($impersonated, 'main', ['ROLE_USER', 'ROLE_PREVIOUS_ADMIN'], $impersonator);

        $this->assertGrantedAlike('ROLE_PREVIOUS_ADMIN');
        $this->assertGrantedAlike('IS_IMPERSONATOR');
    }

    /**
     * Security: $security->isGranted('IS_AUTHENTICATED_FULLY');.
     */
    public function testCheckingTheAuthenticationState(): void
    {
        $this->assertGrantedAlike('IS_AUTHENTICATED_FULLY');
        $this->assertGrantedAlike('IS_REMEMBERED');
    }

    /**
     * Security: $security->isGranted('PUBLIC_ACCESS');.
     */
    public function testCheckingPublicAccess(): void
    {
        $this->assertGrantedAlike('PUBLIC_ACCESS');
    }

    /**
     * Security: $security->isGranted(new Expression('"ROLE_ADMIN" in role_names'));.
     *
     * Covers every variable and function both expression languages share.
     */
    #[DataProvider('provideSharedExpressions')]
    public function testCheckingAnExpression(string $expression): void
    {
        $this->assertGrantedAlike(new Expression($expression));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSharedExpressions(): iterable
    {
        yield 'role_names' => ['"ROLE_ADMIN" in role_names'];
        yield 'role_names, denied' => ['"ROLE_MODERATOR" in role_names'];
        yield 'role_names, reached through the hierarchy' => ['"ROLE_USER" in role_names'];
        yield 'user' => ['user.getUserIdentifier() === "bob"'];
        yield 'token' => ['token !== null'];
        yield 'subject' => ['subject === null'];
        yield 'object' => ['object === null'];
        yield 'is_authenticated()' => ['is_authenticated()'];
        yield 'is_fully_authenticated()' => ['is_fully_authenticated()'];
        yield 'is_remember_me()' => ['is_remember_me()'];
        yield 'trust_resolver' => ['trust_resolver.isFullFledged(token)'];
        yield 'is_granted()' => ['is_granted("ROLE_ADMIN")'];
        yield 'is_granted(), denied' => ['is_granted("ROLE_MODERATOR")'];
        yield 'is_granted() on a subject' => ['is_granted("read", subject)'];
        yield 'auth_checker' => ['auth_checker.isGranted("ROLE_ADMIN")'];
    }

    /**
     * Security: $security->isGranted('read', $post);.
     */
    public function testCheckingAVoterOnASubject(): void
    {
        $post = new Post('Hello');

        $this->assertGrantedAlike('read', $post);
    }

    /**
     * Security: $security->isGranted(fn (IsGrantedContext $context, mixed $subject) => ...).
     *
     * The closure itself cannot be shared, as the two stacks hand it different arguments: Security
     * passes a context and the subject, this component passes the access request, which already
     * carries the subject, plus a checker bound to its requester. The pair below is therefore the
     * translation guide, and both are reached the same way, through a voter, since PHP forbids a
     * closure in the arguments of an attribute.
     */
    public function testAClosureAttribute(): void
    {
        $this->assertTrue($this->security()->isGranted(static fn (IsGrantedContext $context, mixed $subject): bool => $context->isGranted('ROLE_ADMIN')));
        $this->assertSame(
            DecisionVote::ACCESS_GRANTED,
            $this->accessControl()->decide(new AccessRequest($this->token, static fn (AccessRequest $accessRequest, RequesterBoundChecker $checker): bool => $checker->isGranted('ROLE_ADMIN')))->decision,
        );

        $this->assertFalse($this->security()->isGranted(static fn (IsGrantedContext $context, mixed $subject): bool => $context->isGranted('ROLE_SUPER_ADMIN')));
        $this->assertSame(
            DecisionVote::ACCESS_DENIED,
            $this->accessControl()->decide(new AccessRequest($this->token, static fn (AccessRequest $accessRequest, RequesterBoundChecker $checker): bool => $checker->isGranted('ROLE_SUPER_ADMIN')))->decision,
        );
    }

    /**
     * Security: an access_decision_manager configured with strategy: unanimous.
     */
    public function testCheckingUnderTheDenyOverridesStrategy(): void
    {
        $this->assertGrantedAlike('ROLE_ADMIN', null, 'deny_overrides');
        $this->assertGrantedAlike('ROLE_SUPER_ADMIN', null, 'deny_overrides');
    }

    /**
     * Security: an access_decision_manager configured with strategy: consensus.
     */
    public function testCheckingUnderTheMajorityStrategy(): void
    {
        $this->assertGrantedAlike('ROLE_ADMIN', null, 'majority');
        $this->assertGrantedAlike('ROLE_SUPER_ADMIN', null, 'majority');
    }

    /**
     * Security: an access_decision_manager configured with strategy: priority.
     */
    public function testCheckingUnderTheFirstApplicableStrategy(): void
    {
        $this->assertGrantedAlike('ROLE_ADMIN', null, 'first_applicable');
        $this->assertGrantedAlike('ROLE_SUPER_ADMIN', null, 'first_applicable');
    }

    /**
     * Security: $security->isGrantedForUser($user, 'ROLE_ADMIN');.
     *
     * This is the concept that has no façade here: the requester is simply part of the question,
     * so the manager answers it without a dedicated method nor an ambient token stack.
     */
    public function testCheckingForSomeoneElseThanTheCurrentRequester(): void
    {
        $this->assertGrantedAlikeFor(new InMemoryUser('alice', null, ['ROLE_SUPER_ADMIN']), 'ROLE_ALLOWED_TO_SWITCH');
        $this->assertGrantedAlikeFor(new InMemoryUser('carol', null, ['ROLE_USER']), 'ROLE_ALLOWED_TO_SWITCH');
        $this->assertGrantedAlikeFor(new InMemoryUser('alice', null, ['ROLE_USER']), 'read', new Post('Hello'));
    }

    /**
     * Security: $security->isGrantedForUser($user, 'IS_AUTHENTICATED_FULLY'); throws, because it wraps
     * the user in an offline token and an authentication state is undefined outside a session.
     *
     * Here the user is passed as is, so the voter abstains and the decision falls back to a denial
     * carrying the reason. Both refuse to answer, Security loudly and this component quietly.
     *
     * Known and accepted difference: pinned here so it cannot drift further unnoticed.
     */
    public function testAskingAnAuthenticationQuestionAboutSomeoneElse(): void
    {
        $someoneElse = new InMemoryUser('alice', null, ['ROLE_SUPER_ADMIN']);

        try {
            $this->security()->isGrantedForUser($someoneElse, 'IS_AUTHENTICATED_FULLY');
            $this->fail('Security should have refused to answer.');
        } catch (InvalidArgumentException) {
        }

        $decision = $this->accessControl()->decide(new AccessRequest($someoneElse, 'IS_AUTHENTICATED_FULLY'));

        $this->assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
        $this->assertStringContainsString('The requester is not an instance of TokenInterface.', (string) $decision->reason);
    }

    /**
     * Security: an offline token stands for a user considered outside any session. This is what
     * isGrantedForUser() builds internally.
     */
    public function testCheckingWithAnOfflineToken(): void
    {
        $this->token = $this->createOfflineToken();

        $this->assertGrantedAlike('PUBLIC_ACCESS');
        $this->assertGrantedAlike('ROLE_ADMIN');
        $this->assertGrantedAlike('ROLE_SUPER_ADMIN');
    }

    /**
     * Both stacks refuse to answer an authentication question about an offline token, and they
     * refuse it the same way. The difference pinned above therefore lies in what isGrantedForUser()
     * builds, not in the voters.
     */
    public function testAnOfflineTokenRefusesAuthenticationQuestionsInBothStacks(): void
    {
        $this->token = $this->createOfflineToken();

        $this->expectException(InvalidArgumentException::class);
        $this->accessControl()->decide(new AccessRequest($this->token, 'IS_AUTHENTICATED_FULLY'));
    }

    public function testSecurityAlsoRefusesAuthenticationQuestionsAboutAnOfflineToken(): void
    {
        $this->token = $this->createOfflineToken();

        $this->expectException(InvalidArgumentException::class);
        $this->security()->isGranted('IS_AUTHENTICATED_FULLY');
    }

    private function createOfflineToken(): TokenInterface
    {
        $token = new class(['ROLE_ADMIN']) extends AbstractToken implements OfflineTokenInterface {};
        $token->setUser(new InMemoryUser('bob', null, ['ROLE_ADMIN']));

        return $token;
    }

    private function assertGrantedAlikeFor(UserInterface $user, mixed $attribute, mixed $subject = null): void
    {
        $securityGranted = $this->security()->isGrantedForUser($user, $attribute, $subject);
        $decision = $this->accessControl()->decide(new AccessRequest($user, $attribute, $subject));

        $this->assertSame(
            $securityGranted,
            DecisionVote::ACCESS_GRANTED === $decision->decision,
            \sprintf('Security and AccessControl disagree on "%s" for another requester.', var_export($attribute, true)),
        );
    }

    private function assertGrantedAlike(mixed $attribute, mixed $subject = null, ?string $strategy = null): void
    {
        $securityGranted = $this->security($strategy)->isGranted($attribute, $subject);
        $decision = $this->accessControl()->decide(new AccessRequest($this->token, $attribute, $subject), $strategy);

        $this->assertSame(
            $securityGranted,
            DecisionVote::ACCESS_GRANTED === $decision->decision,
            \sprintf('Security and AccessControl disagree on "%s".', get_debug_type($attribute).' '.var_export($attribute, true)),
        );
    }

    /**
     * The voter list must be replayable: AccessDecisionManager iterates it on every decision, and
     * its ExpressionVoter needs the checker that is built from that very manager.
     *
     * The strategy names are translated here rather than anywhere else, which is where the
     * correspondence the migration will need is spelled out and exercised at once.
     */
    private function security(?string $strategy = null): AuthorizationChecker
    {
        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken($this->token);

        $voters = new class(new AuthenticationTrustResolver(), new SecurityRoleHierarchy(self::HIERARCHY)) implements \IteratorAggregate {
            public ?AuthorizationCheckerInterface $authChecker = null;

            public function __construct(
                private readonly AuthenticationTrustResolverInterface $trustResolver,
                private readonly SecurityRoleHierarchyInterface $roleHierarchy,
            ) {
            }

            public function getIterator(): \Traversable
            {
                yield new SecurityAuthenticatedVoter($this->trustResolver);
                yield new SecurityRoleHierarchyVoter($this->roleHierarchy);
                yield new SecurityExpressionVoter(new SecurityExpressionLanguage(), $this->trustResolver, $this->authChecker, $this->roleHierarchy);
                yield new SecurityClosureVoter($this->authChecker);
                yield new SecurityPostVoter();
            }
        };

        $manager = new AccessDecisionManager($voters, match ($strategy) {
            'deny_overrides' => new SecurityUnanimousStrategy(),
            'majority' => new SecurityConsensusStrategy(),
            'first_applicable' => new SecurityPriorityStrategy(),
            default => new SecurityAffirmativeStrategy(),
        });

        return $voters->authChecker = new AuthorizationChecker($tokenStorage, $manager);
    }

    private function accessControl(): AccessControlManagerInterface
    {
        $trustResolver = new AuthenticationTrustResolver();
        $roleHierarchy = new RoleHierarchy(self::HIERARCHY);
        $manager = null;

        $voters = (static function () use (&$manager, $trustResolver, $roleHierarchy) {
            yield new AuthenticatedVoter($trustResolver);
            yield new RoleVoter($roleHierarchy);
            yield new ExpressionVoter(new ExpressionLanguage(), $manager, $trustResolver, $roleHierarchy);
            yield new ClosureVoter($manager);
            yield new PostVoter();
        })();

        return $manager = new AccessControlManager([new PermitOverridesStrategy(), new DenyOverridesStrategy(), new MajorityStrategy(), new FirstApplicableStrategy()], $voters);
    }
}
