<?php

declare(strict_types=1);

namespace AccessControl\Tests\Listener;

use PHPUnit\Framework\TestCase;
use AccessControl\Http\AccessRule;
use AccessControl\Http\AccessRuleMap;
use AccessControl\Listener\ChannelListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher\PathRequestMatcher;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

final class ChannelListenerTest extends TestCase
{
    /**
     * Above the access rules and above Security's firewall: a request about to be redirected is not
     * worth authenticating, which is the order Security applies inside its own firewall.
     */
    public function testItRunsBeforeTheFirewallAndBeforeTheAccessRules()
    {
        $this->assertSame(['onKernelRequest', 9], ChannelListener::getSubscribedEvents()[KernelEvents::REQUEST]);
    }

    public function testAnInsecureRequestOnAnHttpsRuleIsRedirected()
    {
        $event = $this->handle('http://localhost/secure/area', 'https');

        $this->assertInstanceOf(RedirectResponse::class, $response = $event->getResponse());
        $this->assertSame('https://localhost/secure/area', $response->getTargetUrl());
        $this->assertSame(301, $response->getStatusCode());
    }

    public function testASecureRequestOnAnHttpRuleIsRedirected()
    {
        $event = $this->handle('https://localhost/plain', 'http');

        $this->assertSame('http://localhost/plain', $event->getResponse()->getTargetUrl());
    }

    public function testARequestAlreadyOnTheRightChannelIsLeftAlone()
    {
        $this->assertNull($this->handle('https://localhost/secure/area', 'https')->getResponse());
        $this->assertNull($this->handle('http://localhost/plain', 'http')->getResponse());
    }

    public function testARuleWithoutAChannelIsLeftAlone()
    {
        $this->assertNull($this->handle('http://localhost/anything', null)->getResponse());
    }

    public function testARequestNoRuleCoversIsLeftAlone()
    {
        $map = new AccessRuleMap([new AccessRule(new PathRequestMatcher('^/secure'), null, 'https')]);
        $event = $this->requestEvent('http://localhost/public');

        (new ChannelListener($map))->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testASubRequestIsLeftAlone()
    {
        $map = new AccessRuleMap([new AccessRule(new PathRequestMatcher('^/'), null, 'https')]);
        $event = $this->requestEvent('http://localhost/secure', HttpKernelInterface::SUB_REQUEST);

        (new ChannelListener($map))->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testTheQueryStringSurvivesTheRedirection()
    {
        $event = $this->handle('http://localhost/secure?page=2&sort=name', 'https');

        $this->assertSame('https://localhost/secure?page=2&sort=name', $event->getResponse()->getTargetUrl());
    }

    public function testNonStandardPortsAreCarriedOver()
    {
        $map = new AccessRuleMap([new AccessRule(new PathRequestMatcher('^/'), null, 'https')]);
        $event = $this->requestEvent('http://localhost/secure');

        (new ChannelListener($map, null, 8080, 8443))->onKernelRequest($event);

        $this->assertSame('https://localhost:8443/secure', $event->getResponse()->getTargetUrl());
    }

    /**
     * A channel is not an access decision, so nothing is asked of any voter and nothing reaches the
     * decision log. The listener takes no evaluator at all, which is how that is guaranteed.
     */
    public function testEnforcingAChannelAsksNobody()
    {
        $this->assertSame(1, (new \ReflectionMethod(ChannelListener::class, '__construct'))->getNumberOfRequiredParameters());
    }

    private function handle(string $uri, ?string $channel): RequestEvent
    {
        $map = new AccessRuleMap([new AccessRule(new PathRequestMatcher('^/'), null, $channel)]);
        $event = $this->requestEvent($uri);

        (new ChannelListener($map))->onKernelRequest($event);

        return $event;
    }

    private function requestEvent(string $uri, int $type = HttpKernelInterface::MAIN_REQUEST): RequestEvent
    {
        return new RequestEvent($this->createStub(HttpKernelInterface::class), Request::create($uri), $type);
    }
}
