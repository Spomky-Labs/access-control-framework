<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\AccessControlBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The very same application, with and without the bundle registered.
 *
 * Registering it points security.access.decision_manager at the component, so #[IsGranted] stops
 * being answered by Security and starts being answered by AccessControl without a line changing in
 * security.yaml. The security configuration below is therefore identical in both cases, on purpose.
 */
class SecurityParityKernel extends Kernel
{
    use MicroKernelTrait;

    public function __construct(
        private readonly bool $switched
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();

        if ($this->switched) {
            yield new AccessControlBundle();
        }
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(__DIR__ . '/SecurityParityController.php', 'attribute');
    }

    /**
     * Of the rules below, only the roles and the allow_if expression reach the decision manager. The
     * rest is matching, which registering the bundle must leave strictly alone.
     */
    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'router' => [
                'utf8' => true,
            ],
            'test' => true,
        ]);

        $container->loadFromExtension('security', [
            'password_hashers' => [
                InMemoryUser::class => 'plaintext',
            ],
            'providers' => [
                'main' => [
                    'memory' => [
                        'users' => [
                            'alice' => [
                                'password' => 'pa$$word',
                                'roles' => ['ROLE_ADMIN'],
                            ],
                            'bob' => [
                                'password' => 'pa$$word',
                                'roles' => ['ROLE_USER'],
                            ],
                            'carol' => [
                                'password' => 'pa$$word',
                                'roles' => ['ROLE_MANAGER'],
                            ],
                        ],
                    ],
                ],
            ],
            'role_hierarchy' => [
                'ROLE_ADMIN' => ['ROLE_USER'],
            ],
            'firewalls' => [
                'main' => [
                    'pattern' => '^/',
                    'http_basic' => null,
                    'provider' => 'main',
                ],
            ],
            'access_control' => [
                [
                    'path' => '^/dashboard/admin',
                    'roles' => 'ROLE_ADMIN',
                ],
                [
                    'path' => '^/dashboard',
                    'roles' => 'ROLE_USER',
                ],
                [
                    'path' => '^/either',
                    'roles' => ['ROLE_ADMIN', 'ROLE_MANAGER'],
                ],
                [
                    'path' => '^/allow-if',
                    'allow_if' => "is_granted('ROLE_ADMIN') and request.getMethod() == 'GET'",
                ],
                [
                    'path' => '^/by-ip',
                    'ips' => ['10.0.0.1'],
                    'roles' => 'ROLE_SUPER_ADMIN',
                ],
                [
                    'path' => '^/by-ip',
                    'roles' => 'PUBLIC_ACCESS',
                ],
                [
                    'path' => '^/by-method',
                    'methods' => ['POST'],
                    'roles' => 'ROLE_SUPER_ADMIN',
                ],
                [
                    'path' => '^/by-method',
                    'roles' => 'PUBLIC_ACCESS',
                ],
                [
                    'path' => '^/by-host',
                    'host' => 'forbidden\.example\.com',
                    'roles' => 'ROLE_SUPER_ADMIN',
                ],
                [
                    'path' => '^/by-host',
                    'roles' => 'PUBLIC_ACCESS',
                ],
                [
                    'path' => '^/secure-channel',
                    'roles' => 'PUBLIC_ACCESS',
                    'requires_channel' => 'https',
                ],
                [
                    'path' => '^/',
                    'roles' => 'PUBLIC_ACCESS',
                ],
            ],
        ]);

        $container->register(SecurityParityController::class, SecurityParityController::class)
            ->setPublic(true)
            ->addTag('controller.service_arguments');

        $container->register(SecurityApplicationVoter::class, SecurityApplicationVoter::class)
            ->addTag('security.voter');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle/parity-cache' . ($this->switched ? '-switched' : '');
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle/parity-log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
