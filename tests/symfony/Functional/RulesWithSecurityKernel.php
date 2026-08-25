<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\AccessControlBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The two ways of declaring a URL rule, side by side in one application.
 *
 * An application migrating will have both for a while, so they have to hold at the same time: the
 * firewall enforcing its own, the component enforcing ours, and the token serving as requester on
 * both sides.
 */
class RulesWithSecurityKernel extends Kernel
{
    use MicroKernelTrait;

    public function __construct()
    {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new TwigBundle(),
            new SecurityBundle(),
            new AccessControlBundle(),
        ];
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(__DIR__ . '/AccessRulesController.php', 'attribute')->prefix('/rules');
        $routes->import(__DIR__ . '/TwigController.php', 'attribute')->prefix('/rules/twig');
        $routes->import(__DIR__ . '/HelperController.php', 'attribute')->prefix('/rules/helper');
    }

    /**
     * All the rules go on one key: declaring both is refused, the two being a union rather than a
     * choice. The channel goes with them, which is what was silently lost when it followed the mere
     * existence of the firewall's listener.
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
                        ],
                    ],
                ],
            ],
            'firewalls' => [
                'main' => [
                    'pattern' => '^/',
                    'http_basic' => null,
                    'provider' => 'main',
                ],
            ],
        ]);

        $container->loadFromExtension('access_control', [
            'rules' => [
                [
                    'path' => '^/rules/admin',
                    'roles' => ['ROLE_ADMIN'],
                ],
                [
                    'path' => '^/rules/local',
                    'allow_if' => "is_granted('ROLE_ADMIN')",
                ],
                [
                    'path' => '^/rules/staff',
                    'roles' => 'ROLE_ADMIN',
                ],
                [
                    'path' => '^/rules/secure',
                    'roles' => 'PUBLIC_ACCESS',
                    'requires_channel' => 'https',
                ],
            ],
        ]);

        $container->loadFromExtension('twig', [
            'default_path' => __DIR__ . '/templates',
            'strict_variables' => true,
        ]);

        $container->register(AccessRulesController::class, AccessRulesController::class)
            ->setPublic(true)
            ->addTag('controller.service_arguments');

        $container->register(TwigController::class, TwigController::class)
            ->setPublic(true)
            ->addTag('controller.service_arguments');

        $container->register(HelperController::class, HelperController::class)
            ->setPublic(true)
            ->setAutoconfigured(true)
            ->setAutowired(true)
            ->addTag('controller.service_arguments');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-rules/secured-cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-rules/secured-log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
