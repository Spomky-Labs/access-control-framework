<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use AccessControl\AccessControlManager;
use AccessControl\Bridge\Security\AccessDecisionManagerAdapter;
use AccessControl\Bridge\Security\VoterAdapter;
use AccessControl\ExpressionLanguage;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PostVoter;
use AccessControl\Tests\Fixtures\SecurityPostVoter;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use AccessControl\Voter\Expression\ExpressionVoter;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleVoter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter as SecurityAuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleHierarchyVoter as SecurityRoleHierarchyVoter;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException as SecurityInvalidArgumentException;
use Symfony\Component\Security\Core\Role\RoleHierarchy as SecurityRoleHierarchy;
use function sprintf;

/**
 * The decision contract of Security, answered by the component, on the very same questions.
 *
 * This is the widest seam of the migration: security.access.decision_manager is what the
 * access_control rules of the firewall, the authorization checker and the Twig functions all end
 * up calling. The attribute lists below are the ones a security.yaml produces, a rule naming
 * several roles among them.
 */
final class AccessDecisionManagerParityTest extends TestCase
{
    private const array HIERARCHY = [
        'ROLE_ADMIN' => ['ROLE_USER'],
    ];

    public static function provideAttributeLists(): iterable
    {
        yield 'a single held role' => [['ROLE_ADMIN']];
        yield 'a single inherited role' => [['ROLE_USER']];
        yield 'a single role out of reach' => [['ROLE_SUPER_ADMIN']];

        yield 'two roles, one held' => [['ROLE_SUPER_ADMIN', 'ROLE_ADMIN']];
        yield 'two roles, the other held' => [['ROLE_ADMIN', 'ROLE_SUPER_ADMIN']];
        yield 'two roles, neither held' => [['ROLE_SUPER_ADMIN', 'ROLE_NOBODY']];

        yield 'an authentication state' => [['IS_AUTHENTICATED_FULLY']];
        yield 'public access' => [['PUBLIC_ACCESS']];
        yield 'a role and an authentication state' => [['ROLE_SUPER_ADMIN', 'IS_AUTHENTICATED_FULLY']];
        yield 'no attribute at all' => [[]];
    }

    /**
     * The fifth argument is what AccessListener passes, and without it Security refuses more than
     * one attribute outright. It is therefore part of the calling convention of access_control,
     * not an option.
     *
     * @param list<string> $attributes
     */
    #[DataProvider('provideAttributeLists')]
    public function testTheSameAttributesGetTheSameAnswer(array $attributes)
    {
        $token = $this->token();

        static::assertSame(
            $this->security()
                ->decide($token, $attributes, null, null, true),
            $this->accessControl()
                ->decide($token, $attributes, null, null, true),
            sprintf('The two stacks disagree on [%s].', implode(', ', $attributes)),
        );
    }

    /**
     * Security rejects several attributes unless the caller opts in, and the adapter has no reason
     * to be stricter or looser than that. Pinned so the difference is deliberate.
     */
    public function testSeveralAttributesWithoutTheOptInAreRefusedBySecurityOnly()
    {
        $this->expectException(SecurityInvalidArgumentException::class);

        $this->security()
            ->decide($this->token(), ['ROLE_ADMIN', 'ROLE_USER']);
    }

    public function testASubjectIsCarriedThrough()
    {
        $token = $this->token();
        $post = new Post('Hello');

        static::assertSame(
            $this->security()
                ->decide($token, ['read'], $post),
            $this->accessControl()
                ->decide($token, ['read'], $post),
        );
    }

    /**
     * AccessListener hands the decision object over to build its message, so leaving it untouched
     * would make getMessage() fail on an uninitialised property.
     */
    public function testTheDecisionHandedOverIsFilledIn()
    {
        $decision = new AccessDecision();

        $this->accessControl()
            ->decide($this->token(), ['ROLE_SUPER_ADMIN'], null, $decision);

        static::assertFalse($decision->isGranted);
        static::assertStringStartsWith('Access Denied.', $decision->getMessage());
        static::assertNotEmpty($decision->votes);
    }

    /**
     * Who voted, which the decision handed over carries as well. Left to the stack as a whole, a
     * template listing the voters of access_decision() read the manager's class repeated once per
     * vote where it used to read the voters themselves.
     *
     * An application voter is named by its own class and not by the adapter this bridge wrapped it
     * in, which is what Security reported before the switch.
     */
    public function testTheDecisionSaysWhoVoted()
    {
        $decision = new AccessDecision();
        $this->accessControl()
            ->decide($this->token(), ['ROLE_ADMIN'], null, $decision);

        static::assertSame([RoleVoter::class], array_map(static fn ($vote) => $vote->voter, $decision->votes));

        $subject = new AccessDecision();
        $this->accessControl()
            ->decide($this->token(), ['read'], new Post('Hello'), $subject);

        static::assertSame([PostVoter::class], array_map(static fn ($vote) => $vote->voter, $subject->votes));
    }

    /**
     * The voter an application wrote against Security keeps its own name. Reporting VoterAdapter
     * would tell a template about this bridge rather than about the voter that refused, and every
     * bridged voter would read alike.
     */
    public function testABridgedVoterIsNamedByTheClassTheApplicationWrote()
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new VoterAdapter(new SecurityPostVoter())]);
        $decision = new AccessDecision();

        new AccessDecisionManagerAdapter($manager)
            ->decide($this->token(), ['read'], new Post('Hello'), $decision);

        static::assertSame([SecurityPostVoter::class], array_map(static fn ($vote) => $vote->voter, $decision->votes));
    }

    /**
     * AccessListener passes a fifth argument the interface does not declare. The adapter has to
     * accept it, or every access_control rule would fail on an argument count.
     */
    public function testTheListenerCallWithFiveArgumentsIsAccepted()
    {
        $decision = new AccessDecision();

        $granted = $this->accessControl()
            ->decide($this->token(), ['ROLE_ADMIN'], null, $decision, true);

        static::assertTrue($granted);
    }

    private function token(): TokenInterface
    {
        return new FakeToken(new FakeUser(roles: ['ROLE_ADMIN']));
    }

    private function security(): AccessDecisionManagerInterface
    {
        return new AccessDecisionManager([
            new SecurityAuthenticatedVoter(new AuthenticationTrustResolver()),
            new SecurityRoleHierarchyVoter(new SecurityRoleHierarchy(self::HIERARCHY)),
            new SecurityPostVoter(),
        ]);
    }

    private function accessControl(): AccessDecisionManagerInterface
    {
        $roleHierarchy = new RoleHierarchy(self::HIERARCHY);
        $manager = null;

        $voters = (static function () use (&$manager, $roleHierarchy) {
            yield new AuthenticatedVoter(new AuthenticationTrustResolver());
            yield new RoleVoter($roleHierarchy);
            yield new ExpressionVoter(new ExpressionLanguage(), $manager, new AuthenticationTrustResolver(), $roleHierarchy);
            yield new PostVoter();
        })();

        $manager = new AccessControlManager([new PermitOverridesStrategy()], $voters);

        return new AccessDecisionManagerAdapter($manager);
    }
}
