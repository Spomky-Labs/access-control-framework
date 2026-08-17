<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Psr\Log\NullLogger;
use AccessControl\Bundle\AccessControlBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * A workflow whose transition is guarded by an expression, under the three shapes an application
 * can have: SecurityBundle alone, both bundles, and this bundle alone.
 *
 * The third shape did not compile before the guard listener of this component existed, which is
 * what the fixture is here to keep measuring.
 */
class WorkflowGuardKernel extends Kernel
{
    use MicroKernelTrait;

    public const SECURITY = 'security';
    public const BOTH = 'both';
    public const ACCESS_CONTROL = 'access_control';

    /**
     * @param self::* $shape which bundles are registered
     */
    public function __construct(
        private readonly string $shape,
        private readonly string $guard = "is_granted('PUBLISH', subject)",
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();

        if (self::ACCESS_CONTROL !== $this->shape) {
            yield new SecurityBundle();
        }

        if (self::SECURITY !== $this->shape) {
            yield new AccessControlBundle();
        }
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
    }

    /**
     * Two settings are deliberate. Validation loads its constraints from attributes, which defaults
     * to false as soon as Symfony\Bundle\FullStack exists, as it does in this repository: without
     * it the constraint on Article is never loaded and is_valid() answers true on an invalid one,
     * measuring nothing.
     *
     * And there is a second transition out of the same place, guarded by an expression that never
     * holds. Every guard of a workflow is dispatched to the same listener, so that one blocking
     * publish would mean the transition of a GuardExpression is not looked at.
     */
    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'router' => ['utf8' => true],
            'test' => true,
            'validation' => ['enabled' => true, 'enable_attributes' => true],
            'workflows' => [
                'article' => [
                    'type' => 'state_machine',
                    'marking_store' => ['type' => 'method', 'property' => 'marking'],
                    'supports' => [Article::class],
                    'initial_marking' => 'draft',
                    'places' => ['draft', 'published', 'discarded'],
                    'transitions' => [
                        'publish' => [
                            'from' => 'draft',
                            'to' => 'published',
                            'guard' => $this->guard,
                        ],
                        'discard' => [
                            'from' => 'draft',
                            'to' => 'discarded',
                            'guard' => "is_granted('DELETE', subject)",
                        ],
                    ],
                ],
            ],
        ]);

        if (self::ACCESS_CONTROL !== $this->shape) {
            $container->loadFromExtension('security', [
                'password_hashers' => [InMemoryUser::class => 'plaintext'],
                'providers' => ['main' => ['memory' => ['users' => [
                    'alice' => ['password' => 'pa$$word', 'roles' => ['ROLE_ADMIN']],
                ]]]],
                'firewalls' => ['main' => ['pattern' => '^/', 'http_basic' => null, 'provider' => 'main']],
            ]);
        }

        $container->register(PermissionVoter::class, PermissionVoter::class)
            ->setAutoconfigured(true);

        $container->setAlias('test.workflow.article', 'state_machine.article')->setPublic(true);
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/access-control-bundle-workflow/'.$this->shape.'/'.md5($this->guard);
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/access-control-bundle-workflow/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
