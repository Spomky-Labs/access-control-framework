<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Requester\TokenStorageRequesterProvider;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * An application may name a decision manager of its own through
 * security.access_decision_manager.service, which SecurityExtension leaves here as an alias rather
 * than a definition.
 *
 * Reading that as "SecurityBundle is not registered" took the whole bridge out while the Twig
 * functions and #[IsGranted] had already been taken over, so the component answered them off a
 * requester provider that knows nobody. Measured: with a firewall and a logged in user, every
 * requester on this side was anonymous.
 */
final class ApplicationDecisionManagerTest extends WebTestCase
{
    private const array CONFIG = [
        'service' => AlwaysDenyingDecisionManager::class,
    ];

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new StrategyParityKernel(StrategyParityKernel::BOTH, [true], self::CONFIG);
    }

    /**
     * A granting voter under the affirmative default would grant. The refusal is the proof that the
     * manager the application named is still the one answering.
     */
    public function testTheManagerTheApplicationNamedKeepsAnswering()
    {
        $client = static::createClient();
        $client->request('GET', '/strategy-parity', server: [
            'PHP_AUTH_USER' => 'alice',
            'PHP_AUTH_PW' => 'pa$$word',
        ]);

        static::assertSame('denied', $client->getResponse()->getContent());
    }

    /**
     * And the bridge stays alive underneath: the component's own entry points need the requester
     * the firewall established, whoever answers Security's questions.
     */
    public function testTheRequesterIsStillTheOneTheFirewallEstablished()
    {
        static::createClient();

        static::assertInstanceOf(TokenStorageRequesterProvider::class, static::getContainer()->get('access_control.requester_provider'));
    }
}
