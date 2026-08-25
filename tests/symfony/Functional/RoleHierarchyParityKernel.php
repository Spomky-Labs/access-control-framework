<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\AccessControlBundle;
use AccessControl\RequesterBoundChecker;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The same hierarchy under the three shapes an application can have, declared where each shape
 * declares it: security.role_hierarchy for the first two, access_control.role_hierarchy for the
 * third, which has no Security to declare it in.
 */
class RoleHierarchyParityKernel extends Kernel
{
    use MicroKernelTrait;

    public const HIERARCHY = [
        'ROLE_ADMIN' => ['ROLE_USER'],
    ];

    /**
     * @param StrategyParityKernel::* $shape which bundles are registered
     */
    public function __construct(
        private readonly string $shape,
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();

        if ($this->shape !== StrategyParityKernel::ACCESS_CONTROL) {
            yield new SecurityBundle();
        }

        if ($this->shape !== StrategyParityKernel::SECURITY) {
            yield new AccessControlBundle();
        }
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('reached', '/reachable-role')
            ->controller([$this, $this->shape === StrategyParityKernel::ACCESS_CONTROL ? 'answerWithoutSecurity' : 'answer']);
    }

    public function answer(Security $security): Response
    {
        return new Response($security->isGranted('ROLE_USER') ? 'granted' : 'denied');
    }

    public function answerWithoutSecurity(RequesterBoundChecker $checker): Response
    {
        return new Response($checker->isGranted('ROLE_USER') ? 'granted' : 'denied');
    }

    /**
     * The user holds ROLE_ADMIN alone and must reach ROLE_USER through the hierarchy, which is what
     * the parity is about.
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

        if ($this->shape !== StrategyParityKernel::ACCESS_CONTROL) {
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
                'role_hierarchy' => self::HIERARCHY,
            ]);
        }

        if ($this->shape === StrategyParityKernel::SECURITY) {
            return;
        }

        $container->loadFromExtension('access_control', $this->shape === StrategyParityKernel::ACCESS_CONTROL ? [
            'role_hierarchy' => self::HIERARCHY,
        ] : []);

        if ($this->shape === StrategyParityKernel::ACCESS_CONTROL) {
            $container->register('test.requester_provider', HeaderRequesterProvider::class)
                ->setArguments([new Reference('request_stack')]);
            $container->setAlias('access_control.requester_provider', 'test.requester_provider');
        }
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-hierarchy/' . $this->shape;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-hierarchy/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
