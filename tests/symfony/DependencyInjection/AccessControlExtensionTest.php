<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\DependencyInjection;

use PHPUnit\Framework\TestCase;
use AccessControl\Bundle\DependencyInjection\AccessControlExtension;
use AccessControl\AccessControlManagerInterface;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\Bridge\Security\IsGrantedListener;
use AccessControl\Http\AccessRule;
use AccessControl\RequesterBoundChecker;
use AccessControl\Twig\AccessControlExtension as AccessControlTwigExtension;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\HttpFoundation\RequestMatcher\AttributesRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\HostRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\IpsRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\MethodRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\PathRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\PortRequestMatcher;

class AccessControlExtensionTest extends TestCase
{
    /**
     * There is no enabled flag anywhere: registering the bundle is what turns the component on, so
     * an empty configuration must already give a working stack.
     */
    public function testAnEmptyConfigurationWiresTheWholeStack()
    {
        $container = $this->load();

        $this->assertTrue($container->hasDefinition('access_control.manager'));
        $this->assertSame('access_control.manager', (string) $container->getAlias(AccessControlManagerInterface::class));

        $manager = $container->getDefinition('access_control.manager');
        $this->assertEquals(new TaggedIteratorArgument('access_control.strategy'), $manager->getArgument(0));
        $this->assertEquals(new TaggedIteratorArgument('access_control.voter'), $manager->getArgument(1));

        foreach (['permit_overrides', 'deny_overrides', 'majority', 'first_applicable'] as $strategy) {
            $this->assertTrue($container->hasDefinition('access_control.strategy.'.$strategy), $strategy);
        }
    }

    public function testTheDefaults()
    {
        $container = $this->load();

        $this->assertSame('permit_overrides', $container->getParameter('access_control.default_strategy'));
        $this->assertTrue($container->getParameter('access_control.allow_if_equal_granted_denied'));
        $this->assertSame('ROLE_', $container->getParameter('access_control.role_prefix'));
        $this->assertSame([], $container->getParameter('access_control.role_hierarchy.roles'));
    }

    public function testTheConfigurationReachesTheParameters()
    {
        $container = $this->load([
            'default_strategy' => 'deny_overrides',
            'allow_if_equal_granted_denied' => false,
            'role_prefix' => 'PERM_',
        ]);

        $this->assertSame('deny_overrides', $container->getParameter('access_control.default_strategy'));
        $this->assertFalse($container->getParameter('access_control.allow_if_equal_granted_denied'));
        $this->assertSame('PERM_', $container->getParameter('access_control.role_prefix'));
        $this->assertSame('%access_control.role_prefix%', (string) $container->getDefinition('access_control.voter.role')->getArgument(1));
    }

    public function testAStrategyThatIsNotOneOfTheFourIsRejected()
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->load(['default_strategy' => 'affirmative']);
    }

    /**
     * The logger is always registered, an integration test reading it whether a profiler runs or
     * not, and it is reset between two requests so a worker does not grow without bound.
     */
    public function testTheDecisionLoggerIsAlwaysThere()
    {
        $logger = $this->load()->getDefinition('access_control.decision_logger');

        $this->assertSame([[]], $logger->getTag('kernel.event_subscriber'));
        $this->assertSame([['method' => 'reset']], $logger->getTag('kernel.reset'));
    }

    /**
     * The collector is registered unconditionally, as the extension cannot know whether a profiler
     * is configured. Without one, nothing references it and it is dropped as unused.
     */
    public function testTheCollectorIsRegisteredAndDroppedWhenNoProfilerCollectsIt()
    {
        $container = $this->load();

        $this->assertTrue($container->hasDefinition('data_collector.access_control'));

        $container->register('cache.system', \ArrayObject::class);
        $container->compile();

        $this->assertFalse($container->has('data_collector.access_control'));
    }

    /**
     * What a service or a controller injects when it has to decide in the middle of its own work.
     * It is bound to whoever is asking right now, so it needs no requester of its own.
     */
    public function testTheCheckerIsInjectableByType()
    {
        $container = $this->load();

        $this->assertSame(RequesterBoundChecker::class, $container->getDefinition('access_control.checker')->getClass());
        $this->assertSame('access_control.checker', (string) $container->getAlias(RequesterBoundChecker::class));
        $this->assertEquals(new Reference('access_control.requester_provider'), $container->getDefinition('access_control.checker')->getArgument(1));
    }

    /**
     * The attribute belongs to security-http, which can be installed without SecurityBundle being
     * registered. That is exactly the application in the middle of a migration, and the one where
     * nobody used to read #[IsGranted] at all.
     */
    public function testTheIsGrantedListenerIsRegisteredWhenTheAttributeExists()
    {
        $listener = $this->load()->getDefinition('access_control.listener.is_granted');

        $this->assertSame(IsGrantedListener::class, $listener->getClass());
        $this->assertSame([[]], $listener->getTag('kernel.event_subscriber'));
    }

    public function testTheTwigFunctionsAreRegisteredWhenTwigIsThere()
    {
        $extension = $this->load()->getDefinition('access_control.twig.extension');

        $this->assertSame(AccessControlTwigExtension::class, $extension->getClass());
        $this->assertSame([[]], $extension->getTag('twig.extension'));
    }

    /**
     * Nothing of the rule machinery exists until a rule is declared, an application asking for
     * access control on its controllers alone paying for none of it.
     */
    public function testNoRuleMeansNoRuleMachinery()
    {
        $container = $this->load();

        $this->assertFalse($container->hasDefinition('access_control.rule_map'));
        $this->assertFalse($container->hasDefinition('access_control.listener.access_rule'));
        $this->assertFalse($container->hasDefinition('access_control.listener.channel'));
    }

    public function testARuleBecomesAMatcherAndAPolicy()
    {
        $container = $this->load(['rules' => [
            ['path' => '^/admin', 'roles' => ['ROLE_ADMIN']],
        ]]);

        $rules = $container->getDefinition('access_control.rule_map')->getArgument(0);

        $this->assertCount(1, $rules);
        $this->assertSame(AccessRule::class, $rules[0]->getClass());

        $matchers = $rules[0]->getArgument(0)->getArgument(0);
        $this->assertCount(1, $matchers);
        $this->assertSame(PathRequestMatcher::class, $matchers[0]->getClass());
        $this->assertSame('^/admin', $matchers[0]->getArgument(0));

        $accessPolicy = $rules[0]->getArgument(1);
        $this->assertSame(AccessPolicy::class, $accessPolicy->getClass());
        $this->assertSame('ROLE_ADMIN', $accessPolicy->getArgument(0));
        $this->assertNull($rules[0]->getArgument(2));
    }

    /**
     * The request has to reach the voters as the subject, which is what Security's access listener
     * hands its decision manager and what an allow_if expression reads.
     */
    public function testTheRequestIsNamedAsTheSubjectOfEveryRule()
    {
        $container = $this->load(['rules' => [
            ['path' => '^/admin', 'roles' => ['ROLE_ADMIN'], 'allow_if' => "request.getClientIp() == '127.0.0.1'"],
        ]]);

        $accessPolicies = $container->getDefinition('access_control.rule_map')->getArgument(0)[0]->getArgument(1)->getArgument(0);

        foreach ($accessPolicies as $accessPolicy) {
            $this->assertEquals(new Definition(Argument::class, ['request']), $accessPolicy->getArgument(1));
        }
    }

    /**
     * A rule naming several roles is satisfied by any one of them, which is what it has always
     * meant, and AtLeastOneOf is how the component says exactly that.
     */
    public function testSeveralRolesBecomeOneAtLeastOneOf()
    {
        $container = $this->load(['rules' => [
            ['path' => '^/admin', 'roles' => ['ROLE_ADMIN', 'ROLE_MANAGER']],
        ]]);

        $accessPolicy = $container->getDefinition('access_control.rule_map')->getArgument(0)[0]->getArgument(1);

        $this->assertSame(AtLeastOneOf::class, $accessPolicy->getClass());
        $this->assertCount(2, $accessPolicy->getArgument(0));
    }

    public function testAnAllowIfJoinsTheRolesAsOneMoreBranch()
    {
        $container = $this->load(['rules' => [
            ['path' => '^/admin', 'roles' => ['ROLE_ADMIN'], 'allow_if' => "request.getClientIp() == '127.0.0.1'"],
        ]]);

        $accessPolicy = $container->getDefinition('access_control.rule_map')->getArgument(0)[0]->getArgument(1);
        $branches = $accessPolicy->getArgument(0);

        $this->assertSame(AtLeastOneOf::class, $accessPolicy->getClass());
        $this->assertCount(2, $branches);
        $this->assertEquals(new Definition(Expression::class, ["request.getClientIp() == '127.0.0.1'"]), $branches[1]->getArgument(0));
    }

    public function testARuleThatOnlyRequiresAChannelHasNoPolicyAtAll()
    {
        $container = $this->load(['rules' => [
            ['path' => '^/', 'requires_channel' => 'https'],
        ]]);

        $rule = $container->getDefinition('access_control.rule_map')->getArgument(0)[0];

        $this->assertNull($rule->getArgument(1));
        $this->assertSame('https', $rule->getArgument(2));
    }

    /**
     * The channel listener is the only piece that costs something on every request while doing
     * nothing, so it is only registered once a rule actually asks for a channel.
     */
    public function testTheChannelListenerFollowsTheChannels()
    {
        $this->assertFalse($this->load(['rules' => [['path' => '^/', 'roles' => ['ROLE_USER']]]])->hasDefinition('access_control.listener.channel'));
        $this->assertTrue($this->load(['rules' => [['path' => '^/', 'requires_channel' => 'https']]])->hasDefinition('access_control.listener.channel'));
    }

    public function testEveryMatchingOptionReachesItsMatcher()
    {
        $container = $this->load(['rules' => [[
            'path' => '^/admin',
            'host' => 'admin\.example\.com',
            'port' => 8080,
            'methods' => ['post', 'put'],
            'ips' => ['192.168.0.0/16'],
            'attributes' => ['_locale' => 'fr'],
        ]]]);

        $matchers = $container->getDefinition('access_control.rule_map')->getArgument(0)[0]->getArgument(0)->getArgument(0);
        $byClass = [];

        foreach ($matchers as $matcher) {
            $byClass[$matcher->getClass()] = $matcher->getArgument(0);
        }

        $this->assertSame(['POST', 'PUT'], $byClass[MethodRequestMatcher::class]);
        $this->assertSame('^/admin', $byClass[PathRequestMatcher::class]);
        $this->assertSame('admin\.example\.com', $byClass[HostRequestMatcher::class]);
        $this->assertSame(['192.168.0.0/16'], $byClass[IpsRequestMatcher::class]);
        $this->assertSame(['_locale' => 'fr'], $byClass[AttributesRequestMatcher::class]);
        $this->assertSame(8080, $byClass[PortRequestMatcher::class]);
    }

    public function testTheRouteOptionIsOneMoreRequestAttribute()
    {
        $container = $this->load(['rules' => [['route' => 'admin_dashboard', 'roles' => ['ROLE_ADMIN']]]]);

        $matchers = $container->getDefinition('access_control.rule_map')->getArgument(0)[0]->getArgument(0)->getArgument(0);

        $this->assertSame(AttributesRequestMatcher::class, $matchers[0]->getClass());
        $this->assertSame(['_route' => 'admin_dashboard'], $matchers[0]->getArgument(0));
    }

    public function testAnApplicationMatcherIsTakenAsIs()
    {
        $container = $this->load(['rules' => [['request_matcher' => 'app.matcher', 'roles' => ['ROLE_ADMIN']]]]);

        $this->assertEquals(new Reference('app.matcher'), $container->getDefinition('access_control.rule_map')->getArgument(0)[0]->getArgument(0));
    }

    public function testAnApplicationMatcherRulesOutTheOtherMatchingOptions()
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The "request_matcher" option should not be specified alongside other options.');

        $this->load(['rules' => [['request_matcher' => 'app.matcher', 'path' => '^/admin']]]);
    }

    public function testTheRouteOptionAndTheRouteAttributeAreTheSameThingTwice()
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The "route" option should not be specified alongside "attributes._route" option.');

        $this->load(['rules' => [['route' => 'admin', 'attributes' => ['_route' => 'admin']]]]);
    }

    /**
     * A YAML list holding a lone dash gives an entry made of defaults, which would silently cover
     * every request and require nothing.
     */
    public function testAnEmptyRuleIsRejected()
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('One or more access control rules are empty.');

        $this->load(['rules' => [[]]]);
    }

    public function testAnIpThatIsNotOneIsRejected()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('is not a valid IP address');

        $this->load(['rules' => [['path' => '^/', 'ips' => ['not-an-ip'], 'roles' => ['ROLE_USER']]]]);
    }

    public function testRulesAreKeptInDeclarationOrder()
    {
        $container = $this->load(['rules' => [
            ['path' => '^/admin', 'roles' => ['ROLE_ADMIN']],
            ['path' => '^/', 'roles' => ['ROLE_USER']],
        ]]);

        $rules = $container->getDefinition('access_control.rule_map')->getArgument(0);

        $this->assertSame('^/admin', $rules[0]->getArgument(0)->getArgument(0)[0]->getArgument(0));
        $this->assertSame('^/', $rules[1]->getArgument(0)->getArgument(0)[0]->getArgument(0));
    }

    private function load(array $config = []): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.debug', true);
        (new AccessControlExtension())->load([$config], $container);

        return $container;
    }
}
