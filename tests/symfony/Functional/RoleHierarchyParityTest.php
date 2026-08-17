<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * A requester holding ROLE_ADMIN alone must reach ROLE_USER through the hierarchy, under the three
 * shapes an application can have.
 *
 * The first two say the migration: the hierarchy stays in security.yaml and one object serves both
 * stacks through the adapter. The third says the destination, an application that has no Security
 * at all and declares its hierarchy on this component's own key. That third column is what was
 * missing, and it found a promise the configuration could not keep.
 */
class RoleHierarchyParityTest extends WebTestCase
{
    private static string $shape = StrategyParityKernel::SECURITY;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new RoleHierarchyParityKernel(self::$shape);
    }

    public function testTheThreeShapesReachTheInheritedRole()
    {
        $security = $this->answerOf(StrategyParityKernel::SECURITY);
        $both = $this->answerOf(StrategyParityKernel::BOTH);
        $alone = $this->answerOf(StrategyParityKernel::ACCESS_CONTROL);

        $this->assertSame('granted', $security, 'Security did not answer what this test assumes.');
        $this->assertSame($security, $both, 'Installing the bundle changed the answer.');
        $this->assertSame($security, $alone, 'The component alone does not reach the inherited role.');
    }

    private function answerOf(string $shape): string
    {
        self::$shape = $shape;
        self::ensureKernelShutdown();

        $client = static::createClient();
        $client->request('GET', '/reachable-role', server: [
            'PHP_AUTH_USER' => 'alice',
            'PHP_AUTH_PW' => 'pa$$word',
            'HTTP_X_ROLES' => 'ROLE_ADMIN',
        ]);

        return $client->getResponse()->getContent();
    }
}
