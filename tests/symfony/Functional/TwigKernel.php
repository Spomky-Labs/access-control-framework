<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\AccessControlBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * Twig without Security: is_granted() has to answer, since a template that calls it is the second
 * most common way an application asks, right after an attribute on a controller.
 */
class TwigKernel extends Kernel
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
            new AccessControlBundle(),
        ];
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(__DIR__ . '/TwigController.php', 'attribute')->prefix('/twig');
        $routes->import(__DIR__ . '/HelperController.php', 'attribute')->prefix('/helper');
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'router' => [
                'utf8' => true,
            ],
            'test' => true,
        ]);

        $container->loadFromExtension('twig', [
            'default_path' => __DIR__ . '/templates',
            'strict_variables' => true,
        ]);

        $container->register('test.requester_provider', HeaderRequesterProvider::class)
            ->setArguments([new Reference('request_stack')]);
        $container->setAlias('access_control.requester_provider', 'test.requester_provider');

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
        return sys_get_temp_dir() . '/access-control-bundle-twig/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-twig/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
