<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use AccessControl\AccessControlManager;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\RequesterBoundChecker;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Twig\AccessControlExtension;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\Twig\Extension\SecurityExtension as TwigSecurityExtension;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter as SecurityAuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter as SecurityRoleVoter;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The Twig functions of the component against the ones SecurityBundle publishes, so that a template
 * calling is_granted() reads the same whether the application has a firewall or not.
 */
final class TwigFunctionsParityTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string}>
     */
    public static function attributes(): iterable
    {
        yield 'a role the user holds' => ['ROLE_ADMIN'];
        yield 'a role the user does not hold' => ['ROLE_SUPER_ADMIN'];
        yield 'public access' => ['PUBLIC_ACCESS'];
    }

    #[DataProvider('attributes')]
    public function testIsGranted(string $attribute)
    {
        static::assertSame(
            $this->securityExtension()
                ->isGranted($attribute),
            $this->accessControlExtension()
                ->isGranted($attribute),
            $attribute,
        );
    }

    #[DataProvider('attributes')]
    public function testIsGrantedForUser(string $attribute)
    {
        $user = new InMemoryUser('alice', null, ['ROLE_ADMIN']);

        static::assertSame(
            $this->securityExtension()
                ->isGrantedForUser($user, $attribute),
            $this->accessControlExtension()
                ->isGrantedForUser($user, $attribute),
            $attribute,
        );
    }

    /**
     * The divergence that had to be closed. Security wraps the user in an offline token, which its
     * AuthenticatedVoter rejects, so asking about someone else's authentication state raises. The
     * component cannot wrap, a wrapper hiding the requester from every voter that reads its type,
     * so it states the invariant at the entry point instead. Answering false quietly, which is what
     * it did first, was fail-closed but silent where both other stacks shout.
     */
    #[DataProvider('authenticationStates')]
    public function testAnAuthenticationStateIsRefusedForAnotherRequester(string $attribute)
    {
        $user = new InMemoryUser('alice', null, ['ROLE_ADMIN']);

        try {
            $this->securityExtension()
                ->isGrantedForUser($user, $attribute);
            static::fail('Security should have refused to answer.');
        } catch (InvalidArgumentException) {
        }

        $this->expectException(InvalidArgumentException::class);

        $this->accessControlExtension()
            ->isGrantedForUser($user, $attribute);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function authenticationStates(): iterable
    {
        yield ['IS_AUTHENTICATED_FULLY'];
        yield ['IS_AUTHENTICATED_REMEMBERED'];
        yield ['IS_AUTHENTICATED'];
        yield ['IS_REMEMBERED'];
        yield ['IS_IMPERSONATOR'];
    }

    private function accessControlExtension(): AccessControlExtension
    {
        $manager = new AccessControlManager(
            [new PermitOverridesStrategy()],
            [new RoleVoter(), new AuthenticatedVoter(new AuthenticationTrustResolver())],
        );

        return new AccessControlExtension(
            new RequesterBoundChecker($manager, new StaticRequesterProvider($this->token())),
            $manager,
        );
    }

    private function securityExtension(): TwigSecurityExtension
    {
        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken($this->token());

        return new TwigSecurityExtension(new AuthorizationChecker(
            $tokenStorage,
            new AccessDecisionManager([new SecurityRoleVoter(), new SecurityAuthenticatedVoter(new AuthenticationTrustResolver())]),
        ));
    }

    private function token(): UsernamePasswordToken
    {
        return new UsernamePasswordToken(new InMemoryUser('alice', null, ['ROLE_ADMIN']), 'main', ['ROLE_ADMIN']);
    }
}
