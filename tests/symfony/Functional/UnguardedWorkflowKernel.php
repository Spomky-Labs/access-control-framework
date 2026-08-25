<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * A guarded workflow with neither Security nor this bundle to apply the guard.
 *
 * This has to keep refusing to compile. The check in FrameworkExtension was widened to accept this
 * component in place of Security, and a widened check is exactly where a guard could start compiling
 * into a transition nobody guards.
 */
class UnguardedWorkflowKernel extends Kernel
{
    use MicroKernelTrait;

    public function __construct()
    {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        return [new FrameworkBundle()];
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'router' => [
                'utf8' => true,
            ],
            'test' => true,
            'workflows' => [
                'article' => [
                    'type' => 'state_machine',
                    'marking_store' => [
                        'type' => 'method',
                        'property' => 'marking',
                    ],
                    'supports' => [Article::class],
                    'initial_marking' => 'draft',
                    'places' => ['draft', 'published'],
                    'transitions' => [
                        'publish' => [
                            'from' => 'draft',
                            'to' => 'published',
                            'guard' => "is_granted('EDIT', subject)",
                        ],
                    ],
                ],
            ],
        ]);
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-workflow/unguarded';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-workflow/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
