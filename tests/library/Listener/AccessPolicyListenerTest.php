<?php

declare(strict_types=1);

namespace AccessControl\Tests\Listener;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Event\AccessDecisionEvent;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Exception\UnsupportedAccessPolicyException;
use AccessControl\Handler\AccessPolicyHandler;
use AccessControl\Handler\AllHandler;
use AccessControl\Handler\AtLeastOneOfHandler;
use AccessControl\Listener\AccessPolicyListener;
use AccessControl\Requester\RequesterProviderInterface;
use AccessControl\Requester\TokenStorageRequesterProvider;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\AccessControlledController;
use AccessControl\Tests\Fixtures\FakeEventDispatcher;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeTokenStorage;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\FixedOutcomeVoter;
use AccessControl\Tests\Fixtures\InapplicableHandler;
use AccessControl\Tests\Fixtures\NotHandler;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PostVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Attribute\WithHttpStatus;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class AccessPolicyListenerTest extends TestCase
{
    private PostVoter $postVoter;

    public function testLeafPolicyIsGranted(): void
    {
        $this->createListener()->onKernelControllerArguments($this->createEvent('granted'));

        $this->expectNotToPerformAssertions();
    }

    public function testDenialDoesNotLeakTheInternalDiagnostic(): void
    {
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access Denied.');

        $this->createListener()->onKernelControllerArguments($this->createEvent('denied'));
    }

    public function testTheDiagnosticRemainsObservableThroughTheDecisionEvent(): void
    {
        $dispatcher = new FakeEventDispatcher();

        try {
            $this->createListener($dispatcher)->onKernelControllerArguments($this->createEvent('denied'));
            $this->fail('An AccessDeniedException should have been thrown.');
        } catch (AccessDeniedException) {
        }

        $decisionEvents = array_values(array_filter($dispatcher->events, static fn (object $event): bool => $event instanceof AccessDecisionEvent));

        $this->assertCount(1, $decisionEvents);
        $this->assertSame('At least one voter denied access. The user does not have the required role.', $decisionEvents[0]->accessDecision->reason);
    }

    public function testAnInapplicablePolicyDoesNotBlock(): void
    {
        $this->createListener()->onKernelControllerArguments($this->createEvent('inapplicable'));
        $this->createListener()->onKernelControllerArguments($this->createEvent('inapplicableAmongApplicable'));

        $this->expectNotToPerformAssertions();
    }

    public function testAnInapplicablePolicyDoesNotRescueADeniedSibling(): void
    {
        $this->expectException(AccessDeniedException::class);

        $this->createListener()->onKernelControllerArguments($this->createEvent('inapplicableAmongDenied'));
    }

    public function testAllRequiresEveryPolicy(): void
    {
        $this->createListener()->onKernelControllerArguments($this->createEvent('allGranted'));

        $this->expectException(AccessDeniedException::class);

        $this->createListener()->onKernelControllerArguments($this->createEvent('allPartiallyGranted'));
    }

    public function testAtLeastOneOfRequiresASinglePolicy(): void
    {
        $this->createListener()->onKernelControllerArguments($this->createEvent('atLeastOneOfGranted'));

        $this->expectException(AccessDeniedException::class);

        $this->createListener()->onKernelControllerArguments($this->createEvent('atLeastOneOfDenied'));
    }

    public function testCompositesNest(): void
    {
        $this->createListener()->onKernelControllerArguments($this->createEvent('nested'));

        $this->expectNotToPerformAssertions();
    }

    public function testNestedDenialUsesTheOutermostPolicyMessage(): void
    {
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Nope.');

        $this->createListener()->onKernelControllerArguments($this->createEvent('nestedDenied'));
    }

    public function testArgumentReferenceIsResolvedAtRuntime(): void
    {
        $post = new Post('Hello world');

        $this->createListener()->onKernelControllerArguments($this->createEvent('realWorldExample', [$post]));

        $this->assertSame([$post], $this->postVoter->votedOn);
    }

    /**
     * The status travels as an attribute of the exception class rather than as its code, which the
     * console needs for its own exit status. Without a firewall HttpKernel's error listener reads
     * it and answers 403; with one, the exception listener decides instead.
     */
    public function testDenialIsForbiddenAndLetsTheFirewallDecideTheResponse(): void
    {
        try {
            $this->createListener()->onKernelControllerArguments($this->createEvent('denied'));
            $this->fail('An AccessDeniedException should have been thrown.');
        } catch (AccessDeniedException $exception) {
            $attributes = (new \ReflectionClass($exception))->getAttributes(WithHttpStatus::class);

            $this->assertCount(1, $attributes);
            $this->assertSame(403, $attributes[0]->newInstance()->statusCode);
        }
    }

    public function testCustomMessageIsCarriedOver(): void
    {
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Nope.');

        $this->createListener()->onKernelControllerArguments($this->createEvent('deniedWithACustomMessage'));
    }

    public function testControllerWithoutAttributeIsIgnored(): void
    {
        $this->createListener()->onKernelControllerArguments($this->createEvent('noAttribute'));

        $this->expectNotToPerformAssertions();
    }

    public function testUserlandCombinatorNeedsNoChangeToTheComponent(): void
    {
        $this->createListener()->onKernelControllerArguments($this->createEvent('userlandCombinator'));

        $this->expectException(AccessDeniedException::class);

        $this->createListener()->onKernelControllerArguments($this->createEvent('userlandCombinatorDenied'));
    }

    public function testUnhandledPolicyIsReported(): void
    {
        $evaluator = new AccessPolicyEvaluator([new AllHandler()]);

        $this->expectException(UnsupportedAccessPolicyException::class);
        $this->expectExceptionMessage(AccessPolicy::class);

        $evaluator->evaluate(new AccessPolicy('ROLE_ADMIN'), new AccessPolicyContext());
    }

    private function createEvent(string $method, array $arguments = []): ControllerArgumentsEvent
    {
        return new ControllerArgumentsEvent(
            $this->createStub(HttpKernelInterface::class),
            [new AccessControlledController(), $method],
            $arguments,
            new Request(),
            null,
        );
    }

    private function createListener(?FakeEventDispatcher $dispatcher = null): AccessPolicyListener
    {
        $this->postVoter = new PostVoter();

        $manager = new AccessControlManager(
            [new PermitOverridesStrategy()],
            [
                new RoleVoter(),
                $this->postVoter,
                new FixedOutcomeVoter(AccessOutcome::grant('Granted.'), ['not-before', 'internal-ip-address']),
            ],
            dispatcher: $dispatcher,
        );

        $evaluator = new AccessPolicyEvaluator([
            new AccessPolicyHandler($manager),
            new AllHandler(),
            new AtLeastOneOfHandler(),
            new NotHandler(),
            new InapplicableHandler(),
        ]);

        return new AccessPolicyListener($this->createRequesterProvider(), $evaluator);
    }

    private function createRequesterProvider(): RequesterProviderInterface
    {
        $tokenStorage = new FakeTokenStorage();
        $tokenStorage->setToken(new FakeToken(new FakeUser(roles: ['ROLE_ADMIN', 'ROLE_USER'])));

        return new TokenStorageRequesterProvider($tokenStorage);
    }
}
