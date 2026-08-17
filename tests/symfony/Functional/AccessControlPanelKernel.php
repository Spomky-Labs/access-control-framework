<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Psr\Log\NullLogger;
use AccessControl\Bundle\AccessControlBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Bundle\WebProfilerBundle\WebProfilerBundle;
use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessEnvironment;
use AccessControl\AccessRequest;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\All;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\Attribute\When;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * Decides a few things on the way to a page, so that the access control panel has something to show.
 */
class AccessControlPanelKernel extends Kernel
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
            new WebProfilerBundle(),
            new AccessControlBundle(),
        ];
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import($this->profilerRoutes('profiler.php'))->prefix('/_profiler');
        $routes->import($this->profilerRoutes('wdt.php'))->prefix('/_wdt');
        $routes->add('_', '/')->controller('kernel::homepageController');
        $routes->add('quiet', '/quiet')->controller('kernel::quietController');
        $routes->add('all', '/composite/all')->controller('kernel::allController');
        $routes->add('either', '/composite/either')->controller('kernel::eitherController');
        $routes->add('when', '/composite/when')->controller('kernel::whenController');
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'foo-secret',
            'profiler' => ['only_exceptions' => false],
            'router' => ['utf8' => true],
        ]);

        $container->loadFromExtension('web_profiler', [
            'toolbar' => true,
            'intercept_redirects' => false,
        ]);

        $container->register(PermissionVoter::class, PermissionVoter::class)
            ->setAutoconfigured(true);
    }

    private function profilerRoutes(string $file): string
    {
        return \dirname((new \ReflectionClass(WebProfilerBundle::class))->getFileName()).'/Resources/config/routing/'.$file;
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/cache-'.spl_object_hash($this);
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/log-'.spl_object_hash($this);
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }

    /**
     * Three decisions on purpose. The closure is granted by the closure voter and shown as a dump
     * rather than as a plain attribute, and the role is denied because nobody holds one here, every
     * voter abstaining failing closed.
     */
    #[AccessPolicy('EDIT')]
    public function homepageController(AccessControlManagerInterface $accessControlManager): Response
    {
        $accessControlManager->decide(new AccessRequest(null, static fn (): bool => true));

        $accessControlManager->decide(new AccessRequest(null, 'ROLE_ADMIN', new \stdClass(), new AccessEnvironment(['ip' => '10.0.0.1'])));

        return new Response('<html><head></head><body>Homepage Controller.</body></html>');
    }

    public function quietController(): Response
    {
        return new Response('<html><head></head><body>Nothing was decided here.</body></html>');
    }

    /**
     * One route per composite rather than one page carrying the three: the listener throws on the
     * first policy that denies, so a page whose first composite refuses would never evaluate the
     * others.
     *
     * The two nested policies are the same here and in eitherController(), EDIT being granted and
     * DELETE refused. All therefore refuses where AtLeastOneOf grants, and the decisions below
     * cannot say which of the two was written.
     */
    #[All([new AccessPolicy('EDIT'), new AccessPolicy('DELETE')])]
    public function allController(): Response
    {
        return new Response('<html><head></head><body>All Controller.</body></html>');
    }

    #[AtLeastOneOf([new AccessPolicy('EDIT'), new AccessPolicy('DELETE')])]
    public function eitherController(): Response
    {
        return new Response('<html><head></head><body>Either Controller.</body></html>');
    }

    /**
     * A condition that never holds, so the branch never runs: no decision is taken at all and the
     * composite is the only thing that can say why the page was not guarded.
     */
    #[When(new Expression('false'), [new AccessPolicy('DELETE')])]
    public function whenController(): Response
    {
        return new Response('<html><head></head><body>When Controller.</body></html>');
    }
}
