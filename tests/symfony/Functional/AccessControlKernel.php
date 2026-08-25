<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\AccessControlBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * An application that has no Security at all, which is half the point of the component being
 * independent.
 */
class AccessControlKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param bool $withExitCodeListener registers the listener an application writes when it wants
     *                                   an exit code of its own on a console denial
     */
    public function __construct(
        private readonly bool $withExitCodeListener = false
    ) {
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
        $routes->import(__DIR__ . '/AccessControlController.php', 'attribute')->prefix('/access-control');
    }

    /**
     * The profiler is on for every request, not only for exceptions: the console wraps a command to
     * trace it once --profile is used, and that is the shape the policy discovery has to survive.
     */
    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'router' => [
                'utf8' => true,
            ],
            'test' => true,
            'profiler' => [
                'only_exceptions' => false,
            ],
        ]);

        $container->register(PermissionVoter::class, PermissionVoter::class)
            ->setAutoconfigured(true);

        $container->register(AccessControlledCommand::class, AccessControlledCommand::class)
            ->setAutoconfigured(true);

        $container->register(AccessControlController::class, AccessControlController::class)
            ->setPublic(true)
            ->addTag('controller.service_arguments');

        if ($this->withExitCodeListener) {
            $container->register(ConsoleExitCodeListener::class, ConsoleExitCodeListener::class)
                ->setAutoconfigured(true);
        }
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle/cache' . ($this->withExitCodeListener ? '-exit-code' : '');
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
