<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Throwable;

/**
 * The rules of a security.yaml, declared under access_control.rules and enforced with no Security
 * anywhere. Not one controller carries an attribute: what guards them is the configuration alone.
 */
final class AccessRulesTest extends WebTestCase
{
    use AccessControlAssertionsTrait;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new AccessRulesKernel();
    }

    public function testTheRuleThatMatchesFirstIsTheOneThatApplies()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/open');

        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertSame('open', $client->getResponse()->getContent());
        $this->assertAccessWasGrantedOn('PUBLIC_ACCESS');
    }

    /**
     * PUBLIC_ACCESS is the commonest line of an access_control block and it has to be understood
     * without Security, where nothing authenticates and no trust resolver exists.
     */
    public function testPublicAccessIsUnderstoodWithoutSecurity()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/open', server: [
            'HTTP_X_ROLES' => '',
        ]);

        static::assertSame(200, $client->getResponse()->getStatusCode());
    }

    public function testARequesterHoldingTheRoleGetsThrough()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/admin', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertSame('admin', $client->getResponse()->getContent());
        $this->assertAccessWasGrantedOn('ROLE_ADMIN');
    }

    public function testARequesterWithoutTheRoleIsStopped()
    {
        $client = static::createClient();
        $client->catchExceptions(false);

        try {
            $client->request('GET', '/rules/admin', server: [
                'HTTP_X_ROLES' => 'ROLE_USER',
            ]);
            static::fail('Access should have been denied.');
        } catch (Throwable $exception) {
            static::assertStringContainsString('Access Denied', $exception->getMessage());
        }

        $this->assertAccessWasDeniedOn('ROLE_ADMIN');
    }

    /**
     * The controller never runs, the rule having answered on kernel.request. That is the whole
     * difference with an attribute, which is only read once a controller has been resolved.
     */
    public function testADeniedRuleAnswersBeforeTheControllerIsReached()
    {
        AccessRulesController::$reached = [];

        $client = static::createClient();
        $client->request('GET', '/rules/admin', server: [
            'HTTP_X_ROLES' => 'ROLE_USER',
        ]);

        static::assertSame(403, $client->getResponse()->getStatusCode());
        static::assertSame([], AccessRulesController::$reached);

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/rules/admin', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame(['admin'], AccessRulesController::$reached);
    }

    /**
     * A rule naming several roles is satisfied by any one of them. The second branch is tested too:
     * checking only the first would leave a broken one unnoticed.
     */
    public function testAnyOneOfTheRolesOfARuleIsEnough()
    {
        foreach (['ROLE_ADMIN', 'ROLE_MANAGER'] as $role) {
            static::ensureKernelShutdown();
            $client = static::createClient();
            $client->request('GET', '/rules/staff', server: [
                'HTTP_X_ROLES' => $role,
            ]);

            static::assertSame(200, $client->getResponse()->getStatusCode(), $role);
        }
    }

    public function testNoneOfTheRolesOfARuleIsARefusal()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/staff', server: [
            'HTTP_X_ROLES' => 'ROLE_ACCOUNTANT',
        ]);

        static::assertSame(403, $client->getResponse()->getStatusCode());
    }

    /**
     * An allow_if reads the request because the rule hands it over as the subject, which is what
     * Security's own access listener does with its decision manager.
     */
    public function testAnAllowIfExpressionReadsTheRequest()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/local', server: [
            'REMOTE_ADDR' => '10.0.0.1',
        ]);

        static::assertSame(200, $client->getResponse()->getStatusCode());

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/rules/local', server: [
            'REMOTE_ADDR' => '192.168.1.1',
        ]);

        static::assertSame(403, $client->getResponse()->getStatusCode());
    }

    /**
     * The methods of a rule are matching, not deciding: a request the rule does not cover falls
     * through to the next one rather than being refused.
     */
    public function testAMethodNarrowsWhichRequestsTheRuleCovers()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/posted');

        static::assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertAccessWasGrantedOn('PUBLIC_ACCESS');

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('POST', '/rules/posted');

        static::assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertAccessWasDeniedOn('ROLE_ADMIN');
    }

    public function testARouteNamesTheRequestsARuleCovers()
    {
        $client = static::createClient();
        $client->request('GET', '/rules/by-route', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertAccessWasGrantedOn('ROLE_ADMIN');
    }

    public function testARuleRequiringHttpsRedirects()
    {
        $client = static::createClient();
        $client->request('GET', 'http://localhost/rules/secure');

        static::assertSame(301, $client->getResponse()->getStatusCode());
        static::assertSame('https://localhost/rules/secure', $client->getResponse()->headers->get('Location'));
    }

    /**
     * A channel is not an access decision: the redirection happens without asking any voter, and
     * nothing about it lands in the decision log.
     */
    public function testARedirectionToHttpsDecidesNothing()
    {
        $client = static::createClient();
        $client->request('GET', 'http://localhost/rules/secure');

        $this->assertAccessDecisionCount(0);
    }

    public function testARequestAlreadyOnHttpsIsDecidedNormally()
    {
        $client = static::createClient();
        $client->request('GET', 'https://localhost/rules/secure');

        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertSame('secure', $client->getResponse()->getContent());
        $this->assertAccessWasGrantedOn('PUBLIC_ACCESS');
    }
}
