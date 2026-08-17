<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The bundle wired into an application that has no Security at all, which is half the point of the
 * component being independent.
 */
class AccessControlTest extends WebTestCase
{
    use AccessControlAssertionsTrait;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new AccessControlKernel();
    }

    public function testAControllerWithoutAnyPolicyIsUntouched()
    {
        $client = static::createClient();
        $client->request('GET', '/access-control/open');

        $this->assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertAccessDecisionCount(0);
    }

    public function testAGrantedPolicyLetsTheControllerRun()
    {
        $client = static::createClient();
        $client->request('GET', '/access-control/edit');

        $this->assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertSame('edited', $client->getResponse()->getContent());
        $this->assertAccessWasGrantedOn('EDIT');
        $this->assertAccessWasNotDeniedOn('EDIT');
    }

    /**
     * The status code says the door was closed. The assertions say which door, and who closed it,
     * which the response deliberately never tells.
     */
    public function testADeniedPolicyStopsTheController()
    {
        $client = static::createClient();
        $client->catchExceptions(false);

        try {
            $client->request('GET', '/access-control/delete');
            $this->fail('Access should have been denied.');
        } catch (\Throwable $exception) {
            $this->assertStringContainsString('Access Denied', $exception->getMessage());
        }

        $this->assertAccessWasDeniedOn('DELETE');
        $this->assertAccessWasDeniedBy(PermissionVoter::class);
    }

    public function testACompositeRequiresEveryPolicy()
    {
        $client = static::createClient();
        $client->catchExceptions(false);

        try {
            $client->request('GET', '/access-control/both');
            $this->fail('Access should have been denied.');
        } catch (\Throwable) {
        }

        $this->assertAccessWasGrantedOn('EDIT');
        $this->assertAccessWasDeniedOn('DELETE');
    }

    /**
     * The When composite reads the request the entry point handed over, which is how the component
     * covers the methods parameter of #[IsGranted] without knowing anything about HTTP.
     */
    public function testAConditionOnTheRequestIsHonoured()
    {
        $client = static::createClient();
        $client->request('GET', '/access-control/conditional');

        $this->assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertAccessDecisionCount(0);
    }

    public function testTheConditionAppliesWhenItHolds()
    {
        $client = static::createClient();
        $client->catchExceptions(false);

        try {
            $client->request('POST', '/access-control/conditional');
            $this->fail('Access should have been denied.');
        } catch (\Throwable) {
        }

        $this->assertAccessWasDeniedOn('DELETE');
    }

    /**
     * A denial is a 403 even with no firewall in sight, which is not obvious: the response is not
     * produced by Security but by HttpKernel's ErrorListener, reading the #[WithHttpStatus(403)]
     * carried by the exception class itself.
     */
    public function testADenialIsAlreadyA403WithoutAnyFirewall()
    {
        $client = static::createClient();
        $client->request('GET', '/access-control/delete');

        $this->assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertAccessWasDeniedOn('DELETE');
        $this->assertAccessWasDeniedBy(PermissionVoter::class);
    }

    public function testACustomMessageReachesTheException()
    {
        $client = static::createClient();
        $client->catchExceptions(false);

        try {
            $client->request('GET', '/access-control/custom-message');
            $this->fail('Access should have been denied.');
        } catch (\Throwable $exception) {
            $this->assertSame('You may not delete this.', $exception->getMessage());
        }
    }
}
