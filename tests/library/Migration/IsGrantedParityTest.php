<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use AccessControl\AccessControlManager;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Bridge\Security\IsGrantedListener;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Exception\AccessDeniedExceptionInterface;
use AccessControl\ExpressionLanguage;
use AccessControl\Handler\AccessPolicyHandler;
use AccessControl\Handler\AllHandler;
use AccessControl\Handler\AtLeastOneOfHandler;
use AccessControl\Handler\WhenHandler;
use AccessControl\Listener\AccessPolicyListener;
use AccessControl\Requester\TokenStorageRequesterProvider;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\DuallyControlledController;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeTokenStorage;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PostVoter;
use AccessControl\Tests\Fixtures\SecurityPostVoter;
use AccessControl\Voter\Expression\ExpressionVoter;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleVoter;
use IteratorAggregate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage as BaseExpressionLanguage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\ExpressionLanguage as SecurityExpressionLanguage;
use Symfony\Component\Security\Core\Authorization\Voter\ExpressionVoter as SecurityExpressionVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleHierarchyVoter as SecurityRoleHierarchyVoter;
use Symfony\Component\Security\Core\Exception\AccessDeniedException as SecurityAccessDeniedException;
use Symfony\Component\Security\Core\Role\RoleHierarchy as SecurityRoleHierarchy;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface as SecurityRoleHierarchyInterface;
use Symfony\Component\Security\Http\EventListener\IsGrantedAttributeListener;
use Throwable;
use Traversable;
use function sprintf;

/**
 * Runs the very same controller through Security's IsGrantedAttributeListener and through this
 * component's AccessPolicyListener, and requires both to reach the same conclusion.
 *
 * Each method of DuallyControlledController carries the two attributes side by side, so the
 * fixture doubles as the migration guide: what #[IsGranted] says on one line, #[AccessPolicy]
 * says on the next.
 *
 * Left out of this file: the statusCode and exceptionCode parameters, deliberately absent, and a
 * \Closure attribute, which PHP forbids in the arguments of an attribute and which therefore only
 * ever reaches either stack programmatically, through a voter.
 */
final class IsGrantedParityTest extends TestCase
{
    private const array HIERARCHY = [
        'ROLE_ADMIN' => ['ROLE_USER'],
    ];

    public function testARoleTheRequesterHolds(): void
    {
        $this->assertBehavesAlike('heldRole');
    }

    public function testARoleTheRequesterDoesNotReach(): void
    {
        $this->assertBehavesAlike('unreachableRole');
    }

    public function testARoleInheritedThroughTheHierarchy(): void
    {
        $this->assertBehavesAlike('inheritedRole');
    }

    /**
     * Security: #[IsGranted('read', 'post')], where the string names a controller argument.
     * Here the reference is explicit, as a plain string would be a literal subject.
     */
    public function testASubjectTakenFromAControllerArgument(): void
    {
        $this->assertBehavesAlike('subjectTakenFromAnArgument', [new Post('Hello')]);
    }

    public function testAnExpressionAttribute(): void
    {
        $this->assertBehavesAlike('grantingExpression');
        $this->assertBehavesAlike('denyingExpression');
    }

    public function testACustomMessageReachesTheRequesterOnBothSides(): void
    {
        $this->assertBehavesAlike('customMessage');
        static::assertSame('Nope.', $this->denialMessage($this->securityListener(), 'customMessage'));
        static::assertSame('Nope.', $this->denialMessage($this->accessControlListener(), 'customMessage'));
    }

    /**
     * Pinned divergence, and a deliberate one: with no custom message Security hands the voter
     * diagnostic to the requester, naming the very attribute that was missing, where this
     * component answers a bare denial and keeps the diagnostic for the decision event.
     */
    public function testTheDefaultDenialMessageDiffersOnPurpose(): void
    {
        static::assertStringContainsString('ROLE_SUPER_ADMIN', $this->denialMessage($this->securityListener(), 'unreachableRole'));
        static::assertSame('Access Denied.', $this->denialMessage($this->accessControlListener(), 'unreachableRole'));
    }

    /**
     * The two stacks throw unrelated classes and neither knows the other's, Security having to keep
     * working with no trace of this component installed. What makes that a detail rather than a
     * divergence is the bridge listener, which says the denial again in the words the firewall
     * understands; it is covered where it lives, in AccessDeniedExceptionListenerTest.
     */
    public function testEachStackThrowsItsOwnDenial(): void
    {
        $securityDenial = $this->denial($this->securityListener(), 'unreachableRole');
        $accessControlDenial = $this->denial($this->accessControlListener(), 'unreachableRole');

        static::assertInstanceOf(SecurityAccessDeniedException::class, $securityDenial);
        static::assertInstanceOf(AccessDeniedException::class, $accessControlDenial);
        static::assertNotInstanceOf(AccessDeniedExceptionInterface::class, $securityDenial, 'Security is left untouched.');
    }

    /**
     * Security repeats #[IsGranted] and requires every one of them. The counterpart is All,
     * because repeating #[AccessPolicy] would express the same thing far less explicitly.
     */
    public function testSeveralRequirementsOnTheSameController(): void
    {
        $this->assertBehavesAlike('repeatedAndAllGranted');
        $this->assertBehavesAlike('repeatedAndPartiallyGranted');
    }

    /**
     * Security: #[IsGranted('ROLE_SUPER_ADMIN', methods: 'POST')], which steps aside on any other
     * method. The counterpart is a When composite, whose condition speaks about the circumstances
     * the entry point handed over rather than about an HTTP notion the component would have to
     * know of.
     */
    public function testAConditionOnTheHttpMethod(): void
    {
        $this->assertBehavesAlike('filteredOnTheHttpMethod');
        $this->assertBehavesAlike('filteredOnTheHttpMethod', method: 'POST');

        static::assertTrue($this->isGranted($this->accessControlListener(), 'filteredOnTheHttpMethod'));
        static::assertFalse($this->isGranted($this->accessControlListener(), 'filteredOnTheHttpMethod', method: 'POST'));
    }

    /**
     * Security: #[IsGranted($expression, ['post' => 'post'])], where each value of the map names a
     * controller argument and the voter receives the resolved map as its subject.
     */
    public function testAMapOfNamedSubjects(): void
    {
        $this->assertBehavesAlike('mapOfNamedSubjects', [new Post('Hello')]);
        $this->assertBehavesAlike('mapOfNamedSubjects', [new Post('Goodbye')]);
    }

    /**
     * The same #[IsGranted], read by Security and read by the component, on every scenario this
     * file already covers. This is the parity that matters for a migration: the attributes outlive
     * the bundle that used to handle them, and until this listener existed nobody read them once
     * SecurityBundle was gone. No error, no deprecation, a guarded controller answering 200.
     */
    #[DataProvider('scenarios')]
    public function testTheSameAttributeReadByEitherStack(string $controllerMethod, array $arguments, string $method): void
    {
        static::assertSame(
            $this->isGranted($this->securityListener(), $controllerMethod, $arguments, $method),
            $this->isGranted($this->accessControlIsGrantedListener(), $controllerMethod, $arguments, $method),
            sprintf('The two stacks disagree on "%s()" over %s.', $controllerMethod, $method),
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: array<mixed>, 2: string}>
     */
    public static function scenarios(): iterable
    {
        yield 'a role the requester holds' => ['heldRole', [], 'GET'];
        yield 'a role out of reach' => ['unreachableRole', [], 'GET'];
        yield 'a role inherited through the hierarchy' => ['inheritedRole', [], 'GET'];
        yield 'a subject named after a controller argument' => ['subjectTakenFromAnArgument', [new Post('Hello')], 'GET'];
        yield 'a granting expression' => ['grantingExpression', [], 'GET'];
        yield 'a denying expression' => ['denyingExpression', [], 'GET'];
        yield 'a custom message' => ['customMessage', [], 'GET'];
        yield 'several requirements' => ['repeatedAndAllGranted', [], 'GET'];
        yield 'several requirements, one refused' => ['repeatedAndPartiallyGranted', [], 'GET'];
        yield 'a method the attribute steps aside on' => ['filteredOnTheHttpMethod', [], 'GET'];
        yield 'the method the attribute applies to' => ['filteredOnTheHttpMethod', [], 'POST'];
        yield 'a map of named subjects, granted' => ['mapOfNamedSubjects', [new Post('Hello')], 'GET'];
        yield 'a map of named subjects, refused' => ['mapOfNamedSubjects', [new Post('Goodbye')], 'GET'];
        yield 'a subject given as an expression' => ['subjectFromAnExpression', [new Post('Hello')], 'GET'];
        yield 'a map of subjects given as expressions, granted' => ['mapOfSubjectsFromExpressions', [new Post('Hello')], 'GET'];
        yield 'a map of subjects given as expressions, refused' => ['mapOfSubjectsFromExpressions', [new Post('Goodbye')], 'GET'];
    }

    /**
     * A custom message is the one thing both stacks say alike, and it is what an application relies
     * on. The default message is the pinned divergence, kept as it is above.
     */
    public function testACustomMessageSurvivesTheChangeOfStack(): void
    {
        static::assertSame(
            $this->denialMessage($this->securityListener(), 'customMessage'),
            $this->denialMessage($this->accessControlIsGrantedListener(), 'customMessage'),
        );
    }

    private function assertBehavesAlike(string $controllerMethod, array $arguments = [], string $method = 'GET'): void
    {
        static::assertSame(
            $this->isGranted($this->securityListener(), $controllerMethod, $arguments, $method),
            $this->isGranted($this->accessControlListener(), $controllerMethod, $arguments, $method),
            sprintf('Security and AccessControl disagree on "%s()" over %s.', $controllerMethod, $method),
        );
    }

    private function isGranted(IsGrantedAttributeListener|AccessPolicyListener|IsGrantedListener $listener, string $controllerMethod, array $arguments = [], string $method = 'GET'): bool
    {
        try {
            $listener->onKernelControllerArguments($this->createEvent($controllerMethod, $arguments, $method));

            return true;
        } catch (SecurityAccessDeniedException|AccessDeniedExceptionInterface) {
            return false;
        }
    }

    private function denialMessage(IsGrantedAttributeListener|AccessPolicyListener|IsGrantedListener $listener, string $method): string
    {
        return $this->denial($listener, $method)
            ->getMessage();
    }

    private function denial(IsGrantedAttributeListener|AccessPolicyListener|IsGrantedListener $listener, string $method): Throwable
    {
        try {
            $listener->onKernelControllerArguments($this->createEvent($method));
        } catch (SecurityAccessDeniedException|AccessDeniedExceptionInterface $exception) {
            return $exception;
        }

        static::fail(sprintf('"%s()" was expected to be denied.', $method));
    }

    private function createEvent(string $controllerMethod, array $arguments = [], string $method = 'GET'): ControllerArgumentsEvent
    {
        return new ControllerArgumentsEvent(
            static::createStub(HttpKernelInterface::class),
            [new DuallyControlledController(), $controllerMethod],
            $arguments,
            Request::create('/', $method),
            null,
        );
    }

    /**
     * The voter list must be replayable, and its expression voter needs the checker that is built
     * from the very manager the list is given to, hence the lazy generator below.
     */
    private function securityListener(): IsGrantedAttributeListener
    {
        $voters = new class(new SecurityRoleHierarchy(self::HIERARCHY)) implements IteratorAggregate {
            public ?AuthorizationCheckerInterface $authChecker = null;

            public function __construct(
                private readonly SecurityRoleHierarchyInterface $roleHierarchy,
            ) {
            }

            public function getIterator(): Traversable
            {
                yield new SecurityRoleHierarchyVoter($this->roleHierarchy);
                yield new SecurityExpressionVoter(new SecurityExpressionLanguage(), new AuthenticationTrustResolver(), $this->authChecker, $this->roleHierarchy);
                yield new SecurityPostVoter();
            }
        };

        $checker = new AuthorizationChecker($this->tokenStorage(), new AccessDecisionManager($voters));
        $voters->authChecker = $checker;

        return new IsGrantedAttributeListener($checker, new BaseExpressionLanguage());
    }

    private function accessControlListener(): AccessPolicyListener
    {
        return new AccessPolicyListener(new TokenStorageRequesterProvider($this->tokenStorage()), $this->evaluator());
    }

    /**
     * The very same #[IsGranted], read by the component rather than by Security. It exists because
     * nobody reads the attribute at all once SecurityBundle is gone, so a guarded controller used
     * to answer 200 without a word.
     */
    private function accessControlIsGrantedListener(): IsGrantedListener
    {
        return new IsGrantedListener(new TokenStorageRequesterProvider($this->tokenStorage()), $this->evaluator(), new BaseExpressionLanguage());
    }

    private function evaluator(): AccessPolicyEvaluator
    {
        $roleHierarchy = new RoleHierarchy(self::HIERARCHY);
        $manager = null;

        $voters = (static function () use (&$manager, $roleHierarchy) {
            yield new RoleVoter($roleHierarchy);
            yield new ExpressionVoter(new ExpressionLanguage(), $manager, new AuthenticationTrustResolver(), $roleHierarchy);
            yield new PostVoter();
        })();

        $manager = new AccessControlManager([new PermitOverridesStrategy()], $voters);

        return new AccessPolicyEvaluator([
            new AccessPolicyHandler($manager),
            new AllHandler(),
            new AtLeastOneOfHandler(),
            new WhenHandler(new ExpressionLanguage()),
        ]);
    }

    private function tokenStorage(): TokenStorageInterface
    {
        $tokenStorage = new FakeTokenStorage();
        $tokenStorage->setToken(new FakeToken(new FakeUser(roles: ['ROLE_ADMIN'])));

        return $tokenStorage;
    }
}
