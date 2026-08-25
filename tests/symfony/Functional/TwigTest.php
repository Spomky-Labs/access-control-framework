<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\RequesterBoundChecker;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * A template calling is_granted() used to be a syntax error in an application without Security,
 * whichever way it was written, since the function comes from SecurityBundle's Twig extension.
 */
final class TwigTest extends WebTestCase
{
    use AccessControlAssertionsTrait;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new TwigKernel();
    }

    public function testATemplateAsksAndIsAnswered()
    {
        $client = static::createClient();
        $client->request('GET', '/twig/template', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertSame('admin|not-super', trim($client->getResponse()->getContent()));
        $this->assertAccessWasGrantedOn('ROLE_ADMIN');
        $this->assertAccessWasDeniedOn('ROLE_SUPER_ADMIN');
    }

    public function testARequesterHoldingNothingIsRefusedRatherThanErroring()
    {
        $client = static::createClient();
        $client->request('GET', '/twig/template');

        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertSame('not-admin|not-super', trim($client->getResponse()->getContent()));
    }

    /**
     * The other way of asking in the middle of one's own work. AbstractController::isGranted() is
     * still out of reach without Security, so this is what a controller does instead.
     */
    public function testTheCheckerIsInjectableByType()
    {
        $client = static::createClient();
        $client->request('GET', '/twig/injected', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame('granted', $client->getResponse()->getContent());

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/twig/injected', server: [
            'HTTP_X_ROLES' => 'ROLE_USER',
        ]);

        static::assertSame('denied', $client->getResponse()->getContent());
    }

    /**
     * Both used to raise a LogicException telling the developer to install SecurityBundle, in an
     * application that has deliberately chosen not to have one.
     */
    public function testTheControllerHelpersAnswerWithoutSecurity()
    {
        $client = static::createClient();
        $client->request('GET', '/helper/is-granted', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame('granted', $client->getResponse()->getContent());

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/helper/is-granted', server: [
            'HTTP_X_ROLES' => 'ROLE_USER',
        ]);

        static::assertSame('denied', $client->getResponse()->getContent());
        $this->assertAccessWasDeniedOn('ROLE_ADMIN');
    }

    public function testDenyAccessUnlessGrantedAnswersWithoutSecurity()
    {
        $client = static::createClient();
        $client->request('GET', '/helper/deny-unless', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame('reached', $client->getResponse()->getContent());

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->catchExceptions(false);

        try {
            $client->request('GET', '/helper/deny-unless', server: [
                'HTTP_X_ROLES' => 'ROLE_USER',
            ]);
            static::fail('Access should have been denied.');
        } catch (AccessDeniedException $exception) {
            static::assertSame('Administrators only.', $exception->getMessage());
        }
    }

    /**
     * The status code the component's exception carries, which is what an application without a
     * firewall answers on a denial.
     */
    public function testADenialFromAControllerHelperAnswers403()
    {
        $client = static::createClient();
        $client->request('GET', '/helper/deny-unless', server: [
            'HTTP_X_ROLES' => 'ROLE_USER',
        ]);

        static::assertSame(403, $client->getResponse()->getStatusCode());
    }

    /**
     * The attribute outlives the bundle that used to handle it, which is what a migration looks
     * like. Until the component read it too, this answered 200 whatever the requester held: no
     * error, no deprecation, a guarded controller wide open.
     */
    public function testSecuritysAttributeIsStillEnforcedWithoutSecurity()
    {
        $client = static::createClient();
        $client->request('GET', '/helper/is-granted-attribute', server: [
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        static::assertSame('reached', $client->getResponse()->getContent());

        static::ensureKernelShutdown();
        $client = static::createClient();
        $client->request('GET', '/helper/is-granted-attribute', server: [
            'HTTP_X_ROLES' => 'ROLE_USER',
        ]);

        static::assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertAccessWasDeniedOn('ROLE_ADMIN');
    }

    /**
     * statusCode has no counterpart on #[AccessPolicy], deliberately, but the attribute being read
     * here is Security's: whatever it used to answer, it has to keep answering.
     */
    public function testTheStatusCodeOfTheAttributeIsHonoured()
    {
        $client = static::createClient();
        $client->request('GET', '/helper/is-granted-status', server: [
            'HTTP_X_ROLES' => 'ROLE_USER',
        ]);

        static::assertSame(404, $client->getResponse()->getStatusCode());
    }

    public function testTheCheckerIsBoundToWhoeverAsksRightNow()
    {
        static::createClient();

        static::assertInstanceOf(RequesterBoundChecker::class, static::getContainer()->get('access_control.checker'));
    }
}
