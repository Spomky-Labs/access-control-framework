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
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The same application under the three shapes a migration goes through, carrying the four bricks
 * that answer a question about the current requester: a URL rule, the #[IsGranted] attribute, the
 * Twig function, and the helpers of AbstractController.
 *
 * The two first shapes say the migration, same security.yaml with one bundle more. The third says
 * the destination, an application that has no Security at all: the rule moves to this component's
 * own key and the requester comes from a provider of the application rather than from a firewall.
 */
class MigrationParityKernel extends Kernel
{
    use MicroKernelTrait;

    public const SECURITY = 'security';

    public const BOTH = 'both';

    public const ACCESS_CONTROL = 'access_control';

    private const array RULE = [
        'path' => '^/guarded-by-a-rule',
        'roles' => ['ROLE_ADMIN'],
    ];

    /**
     * @param self::* $shape which bundles are registered
     */
    public function __construct(
        private readonly string $shape,
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new TwigBundle();

        if ($this->shape !== self::ACCESS_CONTROL) {
            yield new SecurityBundle();
        }

        if ($this->shape !== self::SECURITY) {
            yield new AccessControlBundle();
        }
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('rule', '/guarded-by-a-rule')
            ->controller([MigrationParityController::class, 'guardedByARule']);
        $routes->add('attribute', '/guarded-by-the-attribute')
            ->controller([MigrationParityController::class, 'guardedByTheAttribute']);
        $routes->add('template', '/template')
            ->controller([MigrationParityController::class, 'template']);
        $routes->add('security_only', '/security-only')
            ->controller([MigrationParityController::class, 'templateOfSecurityOnlyFunctions']);
        $routes->add('component_decision', '/component-decision')
            ->controller([MigrationParityController::class, 'templateOfTheComponentsDecision']);
        $routes->add('helper_is_granted', '/helper/is-granted')
            ->controller([MigrationParityController::class, 'helperIsGranted']);
        $routes->add('helper_deny_unless', '/helper/deny-unless')
            ->controller([MigrationParityController::class, 'helperDenyUnlessGranted']);
    }

    /**
     * The profiler is on so that the collector survives, and with it the record of which stack
     * answers what. The very same rule is then declared on the key of the stack that enforces it,
     * which is the whole point: the application does not write it twice.
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

        $container->loadFromExtension('twig', [
            'default_path' => __DIR__ . '/templates',
            'strict_variables' => true,
        ]);

        if ($this->shape !== self::ACCESS_CONTROL) {
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
                'access_control' => [self::RULE],
            ]);
        }

        if ($this->shape !== self::SECURITY) {
            $container->loadFromExtension('access_control', $this->shape === self::ACCESS_CONTROL ? [
                'rules' => [self::RULE],
            ] : []);
        }

        if ($this->shape === self::ACCESS_CONTROL) {
            $container->register('test.requester_provider', HeaderRequesterProvider::class)
                ->setArguments([new Reference('request_stack')]);
            $container->setAlias('access_control.requester_provider', 'test.requester_provider');
        }

        $container->register(MigrationParityController::class)
            ->setPublic(true)
            ->setAutoconfigured(true)
            ->setAutowired(true)
            ->addTag('controller.service_arguments');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-migration/' . $this->shape;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/access-control-bundle-migration/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
