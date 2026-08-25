<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use AccessControl\Bundle\Twig\SecurityExtensionWithoutAuthorization;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * An application migrating will hold both kinds of rule for a while, so they have to work side by
 * side rather than one replacing the other.
 */
final class RulesWithSecurityTest extends WebTestCase
{
    use AccessControlAssertionsTrait;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new RulesWithSecurityKernel();
    }

    /**
     * The requester of a component rule is the token the firewall put in place, which only holds
     * because the rule listener runs below the firewall on kernel.request.
     */
    public function testAComponentRuleReadsTheTokenTheFirewallEstablished()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/admin', server: $this->credentials('alice'));

        static::assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertAccessWasGrantedOn('ROLE_ADMIN');

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/rules/admin', server: $this->credentials('bob'));

        static::assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertAccessWasDeniedOn('ROLE_ADMIN');
    }

    /**
     * A plain role rule, on the key this application declares them all on. Declaring some here and
     * some under security.access_control is refused: that would be the union of the two rather than
     * one of them, and a rule moved across without the original being deleted would quietly yield
     * the intersection of the two permissions.
     */
    public function testEveryRuleIsEnforcedFromTheOneKeyTheyAreDeclaredOn()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/staff', server: $this->credentials('alice'));

        static::assertSame(200, $client->getResponse()->getStatusCode());

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/rules/staff', server: $this->credentials('bob'));

        static::assertSame(403, $client->getResponse()->getStatusCode());
    }

    /**
     * An allow_if of ours reaches the very same is_granted() a security.yaml expression uses, the
     * expression voter being handed Security's trust resolver once there is a firewall.
     */
    public function testAnAllowIfOfOursCallsIsGranted()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/local', server: $this->credentials('alice'));

        static::assertSame(200, $client->getResponse()->getStatusCode());

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/rules/local', server: $this->credentials('bob'));

        static::assertSame(403, $client->getResponse()->getStatusCode());
    }

    /**
     * The channel goes with the rules rather than with the firewall. Stepping aside on the mere
     * existence of the firewall's channel listener was a silent hole: measured, requires_channel
     * declared on this key with SecurityBundle registered served the page in the clear, ours removed
     * and Security's with an empty map to enforce.
     */
    public function testTheChannelIsEnforcedByWhoeverHoldsTheRules()
    {
        $client = static::createClient();
        $client->request('GET', 'http://localhost/rules/secure', server: $this->credentials('alice'));

        static::assertSame(301, $client->getResponse()->getStatusCode());
        static::assertSame('https://localhost/rules/secure', $client->getResponse()->headers->get('Location'));
        static::assertTrue(static::getContainer()->has('access_control.listener.channel'));
    }

    /**
     * The two functions this component answers become its own the moment the bundle is registered,
     * and Security's extension is left publishing the rest. One of the two has to go rather than
     * face the other: Twig keeps whichever extension was initialised last and says nothing.
     */
    public function testTheTwigFunctionsAreAnsweredByTheComponent()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/twig/template', server: $this->credentials('alice'));

        static::assertSame('admin|not-super', trim($client->getResponse()->getContent()));
        static::assertTrue(static::getContainer()->has('access_control.twig.extension'));
        $this->assertAccessWasGrantedOn('ROLE_ADMIN');
    }

    /**
     * And what this component does not answer is untouched: impersonation is authentication, which
     * stays with Security, so its own extension keeps publishing those.
     */
    public function testSecurityKeepsPublishingWhatTheComponentDoesNotAnswer()
    {
        static::createClient();

        $functions = [];
        foreach (static::getContainer()->get('twig')->getExtension(SecurityExtensionWithoutAuthorization::class)->getFunctions() as $function) {
            $functions[] = $function->getName();
        }

        static::assertContains('impersonation_exit_path', $functions);
        static::assertContains('access_decision', $functions);
        static::assertNotContains('is_granted', $functions);
        static::assertNotContains('is_granted_for_user', $functions);
    }

    public function testTheInjectedCheckerWorksWithAFirewallToo()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/twig/injected', server: $this->credentials('bob'));

        static::assertSame('denied', $client->getResponse()->getContent());
    }

    /**
     * With a firewall, #[IsGranted] is read by this component and Security's own listener steps
     * aside. The decision count is what proves it: two listeners would ask the same question twice,
     * which costs a full round of voters and shows up as two questions in the profiler.
     */
    public function testTheAttributeIsDecidedOnceAndOnlyOnce()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/helper/is-granted-attribute', server: $this->credentials('alice'));

        static::assertSame('reached', $client->getResponse()->getContent());
        static::assertTrue(static::getContainer()->has('access_control.listener.is_granted'));
        static::assertFalse(static::getContainer()->has('controller.is_granted_attribute_listener'));
        $this->assertAccessDecisionCount(1);
    }

    private function credentials(string $user): array
    {
        return [
            'PHP_AUTH_USER' => $user,
            'PHP_AUTH_PW' => 'pa$$word',
        ];
    }
}
