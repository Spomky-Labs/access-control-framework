<?php

declare(strict_types=1);

namespace AccessControl\Tests\Listener;

use AccessControl\AccessControlManager;
use AccessControl\AccessEnvironment;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\Event\AccessQueryEvent;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Handler\AccessPolicyHandler;
use AccessControl\Handler\AllHandler;
use AccessControl\Handler\AtLeastOneOfHandler;
use AccessControl\Http\AccessRule;
use AccessControl\Http\AccessRuleMap;
use AccessControl\Listener\AccessRuleListener;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\FakeEventDispatcher;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Tests\Fixtures\SubjectRecordingVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher\PathRequestMatcher;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

final class AccessRuleListenerTest extends TestCase
{
    /**
     * Security evaluates its access rules inside the firewall, once authentication has run. Ours is
     * a plain kernel listener so that it works without one, which only holds if it stays below the
     * firewall's own priority.
     */
    public function testItRunsAfterTheFirewall()
    {
        static::assertSame(['onKernelRequest', 7], AccessRuleListener::getSubscribedEvents()[KernelEvents::REQUEST]);
    }

    public function testAMatchingRuleThatGrantsLetsTheRequestThrough()
    {
        $this->listenerFor([new AccessRule(new PathRequestMatcher('^/admin'), new AccessPolicy('ROLE_ADMIN'))])
            ->onKernelRequest($this->requestEvent('/admin/users'));

        $this->expectNotToPerformAssertions();
    }

    public function testAMatchingRuleThatDeniesStopsTheRequest()
    {
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessageIsOrContains('Access Denied.');

        $this->listenerFor([new AccessRule(new PathRequestMatcher('^/admin'), new AccessPolicy('ROLE_SUPER_ADMIN'))])
            ->onKernelRequest($this->requestEvent('/admin/users'));
    }

    public function testARequestNoRuleCoversIsLeftAlone()
    {
        $this->listenerFor([new AccessRule(new PathRequestMatcher('^/admin'), new AccessPolicy('ROLE_SUPER_ADMIN'))])
            ->onKernelRequest($this->requestEvent('/public'));

        $this->expectNotToPerformAssertions();
    }

    /**
     * A rule declaring only requires_channel has nothing to decide, and asking anyway would put a
     * decision in the log for a request nobody restricted.
     */
    public function testARuleWithoutAPolicyDecidesNothing()
    {
        $dispatcher = new FakeEventDispatcher();

        $this->listenerFor([new AccessRule(new PathRequestMatcher('^/'), null, 'https')], $dispatcher)
            ->onKernelRequest($this->requestEvent('/admin'));

        static::assertSame([], $dispatcher->events);
    }

    public function testASubRequestIsLeftAlone()
    {
        $this->listenerFor([new AccessRule(new PathRequestMatcher('^/admin'), new AccessPolicy('ROLE_SUPER_ADMIN'))])
            ->onKernelRequest($this->requestEvent('/admin', HttpKernelInterface::SUB_REQUEST));

        $this->expectNotToPerformAssertions();
    }

    public function testTheMessageOfThePolicyIsCarriedOver()
    {
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessageIsOrContains('Staff only.');

        $this->listenerFor([new AccessRule(new PathRequestMatcher('^/'), new AccessPolicy('ROLE_SUPER_ADMIN', message: 'Staff only.'))])
            ->onKernelRequest($this->requestEvent('/admin'));
    }

    /**
     * The roles of a rule are satisfied by any one of them, which is what a rule naming several
     * roles has always meant. The second branch has to be tested too: only checking the first would
     * leave a broken one unnoticed.
     */
    public function testAnyOneOfTheRolesIsEnough()
    {
        $rule = new AccessRule(new PathRequestMatcher('^/'), new AtLeastOneOf([
            new AccessPolicy('ROLE_SUPER_ADMIN'),
            new AccessPolicy('ROLE_ADMIN'),
        ]));

        $this->listenerFor([$rule])->onKernelRequest($this->requestEvent('/admin'));

        $this->expectNotToPerformAssertions();
    }

    public function testNoneOfTheRolesIsARefusal()
    {
        $rule = new AccessRule(new PathRequestMatcher('^/'), new AtLeastOneOf([
            new AccessPolicy('ROLE_SUPER_ADMIN'),
            new AccessPolicy('ROLE_ACCOUNTANT'),
        ]));

        $this->expectException(AccessDeniedException::class);

        $this->listenerFor([$rule])->onKernelRequest($this->requestEvent('/admin'));
    }

    /**
     * The request has to reach the voters as the subject, which is what Security's own access
     * listener hands its decision manager, and what an allow_if expression reads.
     */
    public function testTheRequestIsHandedOverAsTheSubject()
    {
        $voter = new SubjectRecordingVoter('ROLE_ADMIN');
        $event = $this->requestEvent('/admin');

        $this->listenerFor(
            [new AccessRule(new PathRequestMatcher('^/'), new AccessPolicy('ROLE_ADMIN', new Argument('request')))],
            voters: [$voter],
        )->onKernelRequest($event);

        static::assertSame([$event->getRequest()], $voter->subjects);
        static::assertSame([
            AccessEnvironment::REQUEST => $event->getRequest(),
        ], $voter->environment[0]);
    }

    /**
     * Everything a rule decides belongs to one question, which is what the profiler groups on.
     */
    public function testTheQuestionIsNamedAfterTheRules()
    {
        $dispatcher = new FakeEventDispatcher();

        $this->listenerFor([new AccessRule(new PathRequestMatcher('^/'), new AccessPolicy('ROLE_ADMIN'))], $dispatcher)
            ->onKernelRequest($this->requestEvent('/admin'));

        $queries = array_values(array_filter($dispatcher->events, static fn (object $event): bool => $event instanceof AccessQueryEvent));

        static::assertCount(1, $queries);
        static::assertSame('access_control.rules', $queries[0]->origin);
    }

    /**
     * @param list<AccessRule>  $rules
     * @param list<object>|null $voters
     */
    private function listenerFor(array $rules, ?FakeEventDispatcher $dispatcher = null, ?array $voters = null): AccessRuleListener
    {
        $manager = new AccessControlManager(
            [new PermitOverridesStrategy()],
            $voters ?? [new RoleVoter()],
            dispatcher: $dispatcher,
        );

        $evaluator = new AccessPolicyEvaluator([
            new AccessPolicyHandler($manager),
            new AllHandler(),
            new AtLeastOneOfHandler(),
        ], $dispatcher);

        return new AccessRuleListener(
            new AccessRuleMap($rules),
            new StaticRequesterProvider(new StandaloneRequester(['ROLE_ADMIN'])),
            $evaluator,
        );
    }

    private function requestEvent(string $path, int $type = HttpKernelInterface::MAIN_REQUEST): RequestEvent
    {
        return new RequestEvent(static::createStub(HttpKernelInterface::class), Request::create($path), $type);
    }
}
