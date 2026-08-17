<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Psr\Log\NullLogger;
use AccessControl\Bundle\AccessControlBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * URL rules in an application that has no Security: the rules are the ones a security.yaml would
 * declare, word for word, and nothing but the key they live under changes.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
class AccessRulesKernel extends Kernel
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
            new AccessControlBundle(),
        ];
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(__DIR__.'/AccessRulesController.php', 'attribute')->prefix('/rules');
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'router' => ['utf8' => true],
            'test' => true,
        ]);

        $container->loadFromExtension('access_control', [
            'rules' => [
                ['path' => '^/rules/admin', 'roles' => ['ROLE_ADMIN']],
                ['path' => '^/rules/staff', 'roles' => ['ROLE_ADMIN', 'ROLE_MANAGER']],
                ['path' => '^/rules/local', 'allow_if' => "request.getClientIp() == '10.0.0.1'"],
                ['path' => '^/rules/posted', 'methods' => ['POST'], 'roles' => ['ROLE_ADMIN']],
                ['path' => '^/rules/secure', 'requires_channel' => 'https', 'roles' => ['PUBLIC_ACCESS']],
                ['route' => 'access_rules_by_route', 'roles' => ['ROLE_ADMIN']],
                ['path' => '^/rules', 'roles' => ['PUBLIC_ACCESS']],
            ],
        ]);

        $container->register('test.requester_provider', HeaderRequesterProvider::class)
            ->setArguments([new Reference('request_stack')]);
        $container->setAlias('access_control.requester_provider', 'test.requester_provider');

        $container->register(AccessRulesController::class, AccessRulesController::class)
            ->setPublic(true)
            ->addTag('controller.service_arguments');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/access-control-bundle-rules/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/access-control-bundle-rules/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
