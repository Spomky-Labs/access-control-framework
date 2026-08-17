<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Psr\Log\NullLogger;
use AccessControl\Bundle\AccessControlBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use AccessControl\RequesterBoundChecker;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The same question, the same voters, under the three shapes an application can have: SecurityBundle
 * alone, both bundles, and this bundle alone.
 */
class StrategyParityKernel extends Kernel
{
    use MicroKernelTrait;

    public const SECURITY = 'security';
    public const BOTH = 'both';
    public const ACCESS_CONTROL = 'access_control';

    /**
     * @param self::*      $shape           which bundles are registered
     * @param list<bool>   $voters          one entry per voter, true granting and false denying
     * @param array<mixed> $decisionManager the security.access_decision_manager block
     * @param array<mixed> $accessControl   the access_control block
     * @param string       $attribute       the question asked, THING being the one the fixture voters answer
     */
    public function __construct(
        private readonly string $shape,
        private readonly array $voters,
        private readonly array $decisionManager = [],
        private readonly array $accessControl = [],
        private readonly string $attribute = 'THING',
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
        $routes->add('strategy_parity', '/strategy-parity')->controller([$this, self::ACCESS_CONTROL === $this->shape ? 'answerWithoutSecurity' : 'answer']);
    }

    /**
     * NOBODY_ANSWERS_THIS is what tells the all abstain rule apart: no voter of the fixture supports
     * it, so the answer is the rule alone.
     */
    public function answer(Security $security): Response
    {
        return new Response($security->isGranted($this->attribute) ? 'granted' : 'denied');
    }

    public function answerWithoutSecurity(RequesterBoundChecker $checker): Response
    {
        return new Response($checker->isGranted($this->attribute) ? 'granted' : 'denied');
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'router' => ['utf8' => true],
            'test' => true,
        ]);

        if (self::ACCESS_CONTROL !== $this->shape) {
            $container->loadFromExtension('security', [
                'password_hashers' => [InMemoryUser::class => 'plaintext'],
                'providers' => ['main' => ['memory' => ['users' => [
                    'alice' => ['password' => 'pa$$word', 'roles' => ['ROLE_ADMIN']],
                ]]]],
                'firewalls' => ['main' => ['pattern' => '^/', 'http_basic' => null, 'provider' => 'main']],
                'access_decision_manager' => $this->decisionManager,
            ]);
        }

        if (self::SECURITY !== $this->shape) {
            $container->loadFromExtension('access_control', $this->accessControl);
        }

        foreach ($this->voters as $index => $granting) {
            if (self::ACCESS_CONTROL === $this->shape) {
                $container->register('test.voter.'.$index, FixedAccessControlVoter::class)
                    ->setArguments([$granting])
                    ->addTag('access_control.voter');

                continue;
            }

            $container->register('test.voter.'.$index, FixedVoter::class)
                ->setArguments([$granting])
                ->addTag('security.voter');
        }

        $container->register(AlwaysDenyingStrategy::class);
        $container->register(AlwaysDenyingDecisionManager::class);
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/access-control-bundle-strategy/'.$this->shape.'/'.md5(serialize([$this->voters, $this->decisionManager, $this->accessControl, $this->attribute]));
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/access-control-bundle-strategy/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
