<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\DependencyInjection\Compiler;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\Twig\Extension\SecurityExtension;
use AccessControl\Bundle\DependencyInjection\Compiler\SecurityBridgePass;
use AccessControl\Tests\Bundle\Functional\AlwaysDenyingStrategy;
use AccessControl\Bundle\Twig\SecurityExtensionWithoutAuthorization;
use AccessControl\AccessRequest;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\Bridge\Security\AuthorizationCheckerAdapter;
use AccessControl\Bridge\Security\RoleHierarchyAdapter;
use AccessControl\Bridge\Security\StrategyAdapter;
use AccessControl\Bridge\Security\VoterAdapter;
use AccessControl\DecisionVote;
use AccessControl\Strategy\MajorityStrategy;
use AccessControl\Tests\Fixtures\SecurityPostVoter;
use AccessControl\Voter\Expression\ExpressionVoter;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Argument\IteratorArgument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authorization\Strategy\AffirmativeStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\ConsensusStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\PriorityStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\UnanimousStrategy;
use Symfony\Component\Security\Core\Role\RoleHierarchy as SecurityRoleHierarchy;

final class SecurityBridgePassTest extends TestCase
{
    private const SECURITY_OWN_VOTERS = [
        'security.access.simple_role_voter',
        'security.access.role_hierarchy_voter',
        'security.access.authenticated_voter',
        'security.access.expression_voter',
        'security.access.closure_voter',
    ];

    /**
     * The trust resolver is an authentication concern and stays Security's, so the bridge fills it
     * in on the expression voter.
     */
    public function testTheTrustResolverIsHandedOver()
    {
        $container = $this->containerWithAccessControl();

        (new SecurityBridgePass())->process($container);

        $this->assertEquals(
            new Reference('security.authentication.trust_resolver'),
            $container->getDefinition('access_control.voter.expression')->getArgument(2),
        );
    }

    /**
     * The two stacks each held a hierarchy built from the same security.role_hierarchy
     * configuration. One object serves both through the adapter, and an application that replaced
     * security.role_hierarchy is honoured by the component too.
     *
     * The adapter goes this way round and not the other: the component's implementation does not
     * implement Security's interface, so putting it behind security.role_hierarchy would break
     * every application typed against that interface.
     */
    public function testTheRoleHierarchyIsSharedWithSecurity()
    {
        $container = $this->containerWithAccessControl();
        $container->register('security.role_hierarchy', SecurityRoleHierarchy::class)->setArguments([[]]);

        (new SecurityBridgePass())->process($container);

        $this->assertSame('access_control.role_hierarchy.security', (string) $container->getAlias('access_control.role_hierarchy'));
        $this->assertSame(RoleHierarchyAdapter::class, $container->getDefinition('access_control.role_hierarchy.security')->getClass());
        $this->assertEquals(
            new Reference('security.role_hierarchy'),
            $container->getDefinition('access_control.role_hierarchy.security')->getArgument(0),
        );
        $this->assertEquals(
            new Reference('access_control.role_hierarchy'),
            $container->getDefinition('access_control.voter.role')->getArgument(0),
        );
        $this->assertEquals(
            new Reference('access_control.role_hierarchy'),
            $container->getDefinition('access_control.voter.expression')->getArgument(3),
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideStrategies(): iterable
    {
        yield 'affirmative' => [AffirmativeStrategy::class, 'permit_overrides', 'affirmative'];
        yield 'unanimous' => [UnanimousStrategy::class, 'deny_overrides', 'unanimous'];
        yield 'consensus' => [ConsensusStrategy::class, 'majority', 'consensus'];
        yield 'priority' => [PriorityStrategy::class, 'first_applicable', 'priority'];
    }

    /**
     * The four algorithms carry different names on each side, so the correspondence has to be
     * written down somewhere. Read from the definition SecurityExtension built, never from the
     * configuration, which this bundle's extension is not allowed to see.
     *
     * Two consumers owe the developer the word they wrote rather than only the one this component
     * uses: the panel, and access_decision() in a template, which reads it off the decision itself.
     */
    #[DataProvider('provideStrategies')]
    public function testTheChosenAlgorithmIsCarriedOver(string $securityStrategy, string $expected, string $securityName)
    {
        $container = $this->containerWithAccessControl();
        $container->setParameter('.access_control.default_strategy_alias', null);
        $container->getDefinition('security.access.decision_manager')
            ->setArguments([[], new Definition($securityStrategy, [false])]);

        (new SecurityBridgePass())->process($container);

        $this->assertSame($expected, $container->getParameter('access_control.default_strategy'));

        $this->assertSame($securityName, $container->getParameter('.access_control.default_strategy_alias'));
        $this->assertSame($securityName, $container->getDefinition('access_control.access_decision_manager')->getArgument(3));
    }

    public function testTheEqualityRuleOfConsensusIsCarriedOver()
    {
        $container = $this->containerWithAccessControl();
        $container->getDefinition('security.access.decision_manager')
            ->setArguments([[], new Definition(ConsensusStrategy::class, [false, false])]);

        (new SecurityBridgePass())->process($container);

        $this->assertFalse($container->getDefinition('access_control.strategy.majority')->getArgument(0));
    }

    /**
     * An application may name a combining algorithm of its own, which the bridge wraps rather than
     * replaces, exactly as it wraps the voters.
     *
     * What a template reads is then the algorithm the application named, which is what Security
     * reported too, and not the adapter this bridge wrapped it in.
     */
    public function testAnAlgorithmOfTheApplicationIsWrapped()
    {
        $container = $this->containerWithAccessControl();
        $container->register('app.strategy', AlwaysDenyingStrategy::class);
        $container->getDefinition('security.access.decision_manager')
            ->setArguments([[], new Reference('app.strategy')]);

        (new SecurityBridgePass())->process($container);

        $this->assertSame('security', $container->getParameter('access_control.default_strategy'));
        $this->assertSame(StrategyAdapter::class, $container->getDefinition('access_control.strategy.security')->getClass());
        $this->assertEquals(new Reference('app.strategy'), $container->getDefinition('access_control.strategy.security')->getArgument(0));

        $this->assertSame(AlwaysDenyingStrategy::class, $container->getDefinition('access_control.access_decision_manager')->getArgument(3));
    }

    /**
     * Carried by every strategy of Security and by the manager here, so it travels from the argument
     * of the one to the parameter of the other. Left behind, it would deny what the application used
     * to grant, which it never asked for either.
     */
    public function testTheAllAbstainRuleIsCarriedOver()
    {
        $container = $this->containerWithAccessControl();
        $container->getDefinition('security.access.decision_manager')
            ->setArguments([[], new Definition(AffirmativeStrategy::class, [true])]);

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->getParameter('access_control.allow_if_all_abstain'));
    }

    /**
     * And saying the opposite on each key is a contradiction, not a precedence.
     */
    public function testTwoAllAbstainRulesAreRefused()
    {
        $container = $this->containerWithAccessControl();
        $container->setParameter('.access_control.all_abstain_configured', true);
        $container->setParameter('access_control.allow_if_all_abstain', false);
        $container->getDefinition('security.access.decision_manager')
            ->setArguments([[], new Definition(AffirmativeStrategy::class, [true])]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('allow_if_all_abstain');

        (new SecurityBridgePass())->process($container);
    }

    /**
     * Naming two different algorithms is a contradiction, not a precedence: whichever the bridge
     * picked, the other half of the configuration would be a lie.
     */
    public function testTwoAlgorithmsNamedAtOnceAreRefused()
    {
        $container = $this->containerWithAccessControl();
        $container->setParameter('.access_control.strategy_configured', true);
        $container->setParameter('access_control.default_strategy', 'majority');
        $container->getDefinition('security.access.decision_manager')
            ->setArguments([[], new Definition(UnanimousStrategy::class, [false])]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('deny_overrides');

        (new SecurityBridgePass())->process($container);
    }

    /**
     * And an application that named one on this bundle's key alone keeps it, Security having said
     * nothing beyond its own default.
     */
    public function testAnAlgorithmNamedOnThisBundlesKeyAloneSurvives()
    {
        $container = $this->containerWithAccessControl();
        $container->setParameter('.access_control.strategy_configured', true);
        $container->setParameter('access_control.default_strategy', 'permit_overrides');
        $container->getDefinition('security.access.decision_manager')
            ->setArguments([[], new Definition(AffirmativeStrategy::class, [false])]);

        (new SecurityBridgePass())->process($container);

        $this->assertSame('permit_overrides', $container->getParameter('access_control.default_strategy'));
    }

    /**
     * The alias wins, so a hierarchy declared on this component's own key would be built and then
     * never consulted: a configuration that silently does nothing.
     */
    public function testAHierarchyDeclaredOnBothKeysIsRefused()
    {
        $container = $this->containerWithAccessControl();
        $container->register('security.role_hierarchy', SecurityRoleHierarchy::class)->setArguments([[]]);
        $container->setParameter('access_control.role_hierarchy.roles', ['ROLE_ADMIN' => ['ROLE_USER']]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('has no Security');

        (new SecurityBridgePass())->process($container);
    }

    /**
     * And an application without Security keeps the one it declared, which is the only place it can
     * declare it.
     */
    public function testAHierarchyOfItsOwnSurvivesWithoutSecurity()
    {
        $container = $this->containerWithAccessControl();
        $container->setParameter('access_control.role_hierarchy.roles', ['ROLE_ADMIN' => ['ROLE_USER']]);

        (new SecurityBridgePass())->process($container);

        $this->assertFalse($container->hasAlias('access_control.role_hierarchy'));
    }

    public function testTheComponentKeepsItsOwnHierarchyWithoutSecuritys()
    {
        $container = $this->containerWithAccessControl();

        (new SecurityBridgePass())->process($container);

        $this->assertFalse($container->hasAlias('access_control.role_hierarchy'));
        $this->assertSame(RoleHierarchy::class, $container->getDefinition('access_control.role_hierarchy')->getClass());
    }

    public function testTheBridgeSurvivesAnAbsentExpressionVoter()
    {
        $container = $this->containerWithAccessControl();
        $container->removeDefinition('access_control.voter.expression');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.voter.authenticated'));
    }

    /**
     * Registering the bundle is the opt-in, and this is where it takes effect: everything that asks
     * Security for a decision is answered by the component from here on.
     */
    public function testTheDecisionManagerIsPointedAtTheComponent()
    {
        $container = $this->containerWithAccessControl();

        (new SecurityBridgePass())->process($container);

        $this->assertSame('access_control.access_decision_manager', (string) $container->getAlias('security.access.decision_manager'));
    }

    /**
     * The extension registers the bridge on the strength of SecurityBundle being installed, which
     * is not the same as it being registered. Without a firewall it has to take itself back out,
     * and hand the requester provider back to the one that needs no token storage.
     */
    public function testTheBridgeRemovesItselfWhenSecurityIsNotRegistered()
    {
        $container = $this->containerWithoutSecurity();

        (new SecurityBridgePass())->process($container);

        $this->assertFalse($container->hasDefinition('access_control.requester_provider.token_storage'));
        $this->assertFalse($container->hasDefinition('access_control.access_decision_manager'));
        $this->assertFalse($container->hasDefinition('access_control.authorization_checker'));
        $this->assertSame('access_control.requester_provider.static', (string) $container->getAlias('access_control.requester_provider'));
    }

    /**
     * PUBLIC_ACCESS is the commonest attribute of an access rule and the voter answers it without
     * any trust resolver, so it survives an application that has no Security at all.
     */
    public function testTheAuthenticatedVoterStaysWithoutSecurity()
    {
        $container = $this->containerWithoutSecurity();

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.voter.authenticated'));
        $this->assertNull($container->getDefinition('access_control.voter.authenticated')->getArgument(0));
    }

    public function testTheTrustResolverReachesTheAuthenticatedVoter()
    {
        $container = $this->containerWithAccessControl();

        (new SecurityBridgePass())->process($container);

        $this->assertEquals(
            new Reference('security.authentication.trust_resolver'),
            $container->getDefinition('access_control.voter.authenticated')->getArgument(0),
        );
    }

    /**
     * An application without Security that names its own requester provider has said what it wants.
     * Putting the empty one back would leave every requester anonymous, and silently: nothing would
     * fail, roles would simply never be held.
     */
    public function testAnApplicationRequesterProviderIsNotUndone()
    {
        $container = $this->containerWithoutSecurity();
        $container->register('app.requester_provider');
        $container->setAlias('access_control.requester_provider', 'app.requester_provider');

        (new SecurityBridgePass())->process($container);

        $this->assertSame('app.requester_provider', (string) $container->getAlias('access_control.requester_provider'));
    }

    /**
     * And where this component holds them, it holds the channel too. Stepping aside on the mere
     * existence of the firewall's listener was a silent hole: measured, requires_channel declared on
     * this component's key with SecurityBundle registered served the page in the clear, ours removed
     * and Security's with an empty map to enforce.
     */
    public function testTheChannelStaysWhereThisComponentHoldsTheRules()
    {
        $container = $this->containerWithAccessControl();
        $container->register('access_control.listener.channel');
        $container->register('access_control.rule_map');
        $container->register('security.channel_listener');
        $container->register('security.access_map');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.listener.channel'));
    }

    /**
     * The rules of security.access_control, enforced by this component rather than by the firewall.
     * Read from the map SecurityExtension filled, so the matcher it built is carried across whole
     * and the whole matching side comes for free.
     *
     * A rule naming several roles becomes an AtLeastOneOf: "roles: [A, B]" has always meant either
     * of them, on whichever key.
     */
    public function testTheRulesOfSecurityAreTakenOver()
    {
        $container = $this->containerWithAccessControl();
        $container->register('security.access_map')
            ->addMethodCall('add', [new Reference('app.matcher'), ['ROLE_ADMIN', new Reference('.security.expression.1')], 'https'])
            ->addMethodCall('add', [new Reference('app.other_matcher'), ['ROLE_USER'], null]);

        (new SecurityBridgePass())->process($container);

        $rules = $container->getDefinition('access_control.rule_map')->getArgument(0);

        $this->assertCount(2, $rules);
        $this->assertEquals(new Reference('app.matcher'), $rules[0]->getArgument(0));
        $this->assertSame('https', $rules[0]->getArgument(2));

        $this->assertSame(AtLeastOneOf::class, $rules[0]->getArgument(1)->getClass());
        $this->assertSame(AccessPolicy::class, $rules[1]->getArgument(1)->getClass());
        $this->assertSame('ROLE_USER', $rules[1]->getArgument(1)->getArgument(0));
    }

    /**
     * And both links leave every firewall, the rules and the channel going together: leaving either
     * would answer the same rule twice.
     */
    public function testTheRulesAreTakenOutOfTheFirewalls()
    {
        $container = $this->containerWithAccessControl();
        $container->register('security.access_map')->addMethodCall('add', [new Reference('app.matcher'), ['ROLE_ADMIN'], null]);
        $container->setParameter('security.firewalls', ['main']);
        $container->register('security.firewall.map.context.main')->setArguments([new IteratorArgument([
            new Reference('security.channel_listener'),
            new Reference('security.firewall.authenticator.main'),
            new Reference('security.access_listener'),
        ])]);

        (new SecurityBridgePass())->process($container);

        $this->assertEquals(
            [new Reference('security.firewall.authenticator.main')],
            $container->getDefinition('security.firewall.map.context.main')->getArgument(0)->getValues(),
        );
    }

    /**
     * A rule of Security's that asks for a channel is enforced here too, the channel travelling with
     * the rule. Left to the firewall, it would be enforced off a map nobody consults any more.
     */
    public function testATakenOverRuleKeepsItsChannel()
    {
        $container = $this->containerWithAccessControl();
        $container->register('security.access_map')->addMethodCall('add', [new Reference('app.matcher'), ['PUBLIC_ACCESS'], 'https']);

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.listener.channel'));
        $this->assertSame('https', $container->getDefinition('access_control.rule_map')->getArgument(0)[0]->getArgument(2));
    }

    /**
     * And a rule without one leaves this component's channel listener with nothing to do.
     */
    public function testTheChannelListenerGoesWhenNoRuleAsksForOne()
    {
        $container = $this->containerWithAccessControl();
        $container->register('security.access_map')->addMethodCall('add', [new Reference('app.matcher'), ['ROLE_ADMIN'], null]);

        (new SecurityBridgePass())->process($container);

        $this->assertFalse($container->hasDefinition('access_control.listener.channel'));
    }

    /**
     * Declaring rules on both keys is the union of the two rather than one of them, and a rule moved
     * across without the original being deleted quietly yields the intersection of the permissions.
     */
    public function testTwoSetsOfRulesAreRefused()
    {
        $container = $this->containerWithAccessControl();
        $container->register('access_control.rule_map');
        $container->register('security.access_map')->addMethodCall('add', [null, ['ROLE_ADMIN'], null]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('one key');

        (new SecurityBridgePass())->process($container);
    }

    /**
     * Twig keeps whichever extension is initialised last and says nothing about the other, so two
     * is_granted() functions cannot be left facing each other.
     */
    public function testTheTwigFunctionsAreTakenOverFromSecurity()
    {
        $container = $this->containerWithAccessControl();
        $container->register('access_control.twig.extension');
        $container->register('twig.extension.security', SecurityExtension::class);

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.twig.extension'));
        $this->assertSame(SecurityExtensionWithoutAuthorization::class, $container->getDefinition('twig.extension.security')->getClass());
        $this->assertSame(SecurityExtension::class, $container->getDefinition('access_control.twig.extension.security')->getClass());
        $this->assertSame([], $container->getDefinition('access_control.twig.extension.security')->getTag('twig.extension'));
    }

    public function testTheTwigFunctionsStayWhenSecurityPublishesNone()
    {
        $container = $this->containerWithAccessControl();
        $container->register('access_control.twig.extension');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.twig.extension'));
    }

    /**
     * An application may name a decision manager of its own, which SecurityExtension puts here as an
     * alias rather than a definition. Reading that as "SecurityBundle is not registered" took the
     * whole bridge out: measured, with a firewall and a logged in user, every requester on this side
     * became anonymous while the Twig functions and the attribute had already been taken over.
     */
    public function testAManagerOfTheApplicationKeepsTheBridgeAlive()
    {
        $container = $this->containerWithAccessControl();
        $container->removeDefinition('security.access.decision_manager');
        $container->setAlias('security.access.decision_manager', 'app.decision_manager');
        $container->register('access_control.requester_provider.token_storage');
        $container->setAlias('access_control.requester_provider', 'access_control.requester_provider.token_storage');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.requester_provider.token_storage'));
        $this->assertSame('access_control.requester_provider.token_storage', (string) $container->getAlias('access_control.requester_provider'));
        $this->assertEquals(
            new Reference('security.authentication.trust_resolver'),
            $container->getDefinition('access_control.voter.authenticated')->getArgument(0),
        );
    }

    /**
     * And it keeps answering every question it was chosen to answer. Taking the attribute or the
     * Twig functions over would hand them to an engine the application did not pick.
     */
    public function testAManagerOfTheApplicationIsNeverTakenOver()
    {
        $container = $this->containerWithAccessControl();
        $container->removeDefinition('security.access.decision_manager');
        $container->setAlias('security.access.decision_manager', 'app.decision_manager');
        $container->register('access_control.twig.extension');
        $container->register('twig.extension.security', SecurityExtension::class);
        $container->register('access_control.listener.is_granted');
        $container->register('controller.is_granted_attribute_listener');

        (new SecurityBridgePass())->process($container);

        $this->assertSame('app.decision_manager', (string) $container->getAlias('security.access.decision_manager'));
        $this->assertSame(SecurityExtension::class, $container->getDefinition('twig.extension.security')->getClass());
        $this->assertTrue($container->hasDefinition('controller.is_granted_attribute_listener'));
    }

    /**
     * Registering this bundle is the opt-in, so the attribute is the component's to read from then
     * on. Leaving both listeners would decide it twice.
     */
    public function testTheIsGrantedAttributeIsTakenOverFromSecurity()
    {
        $container = $this->containerWithAccessControl();
        $container->register('access_control.listener.is_granted');
        $container->register('controller.is_granted_attribute_listener');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.listener.is_granted'));
        $this->assertFalse($container->hasDefinition('controller.is_granted_attribute_listener'));
    }

    /**
     * And Security keeps reading it where this component does not, the attribute being of no use to
     * an application that installed the bundle without Twig or without the Security attribute.
     */
    public function testSecurityKeepsReadingTheAttributeWhereTheComponentDoesNot()
    {
        $container = $this->containerWithAccessControl();
        $container->register('controller.is_granted_attribute_listener');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('controller.is_granted_attribute_listener'));
    }

    /**
     * Outside the branch that needs a decision manager, for the same reason as the Twig functions:
     * an attribute decided twice, like an is_granted() left facing another, is silent.
     */
    public function testTheIsGrantedListenerStaysWhenNobodyElseReadsTheAttribute()
    {
        $container = $this->containerWithoutSecurity();
        $container->register('access_control.listener.is_granted');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.listener.is_granted'));
    }

    public function testTheChannelListenerStaysWithoutARuleOfSecuritys()
    {
        $container = $this->containerWithAccessControl();
        $container->register('access_control.listener.channel');

        (new SecurityBridgePass())->process($container);

        $this->assertTrue($container->hasDefinition('access_control.listener.channel'));
    }

    private function containerWithoutSecurity(): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->register('access_control.voter.authenticated')->setArguments([null]);
        $container->register('access_control.requester_provider.static');
        $container->register('access_control.requester_provider.token_storage');
        $container->register('access_control.access_decision_manager')->setArguments([null, null, null, 'permit_overrides']);
        $container->register('access_control.authorization_checker');
        $container->setAlias('access_control.requester_provider', 'access_control.requester_provider.token_storage');

        return $container;
    }

    /**
     * The piece the whole deprecation waits on: an application voter is wrapped rather than
     * dropped, so it keeps being consulted once the component decides.
     */
    public function testAnApplicationVoterIsBridged()
    {
        $container = $this->containerWithAccessControl();
        $container->register('app.post_voter', SecurityPostVoter::class)->addTag('security.voter', ['priority' => 12]);

        (new SecurityBridgePass())->process($container);

        $bridge = $container->getDefinition('access_control.voter.bridge.app.post_voter');

        $this->assertSame(VoterAdapter::class, $bridge->getClass());
        $this->assertEquals(new Reference('app.post_voter'), $bridge->getArgument(0));
        $this->assertSame([['priority' => 12]], $bridge->getTag('access_control.voter'));
    }

    /**
     * The voters Security ships are replaced by native ones, so bridging them too would have every
     * question answered twice. The application's own voter is asserted as still bridged, so the
     * exclusion is not simply doing nothing.
     */
    public function testTheVotersSecurityShipsAreNotBridged()
    {
        $container = $this->containerWithAccessControl();
        foreach (self::SECURITY_OWN_VOTERS as $id) {
            $container->register($id)->addTag('security.voter');
        }

        $container->register('app.post_voter', SecurityPostVoter::class)->addTag('security.voter');

        (new SecurityBridgePass())->process($container);

        foreach (self::SECURITY_OWN_VOTERS as $id) {
            $this->assertFalse($container->hasDefinition('access_control.voter.bridge.'.$id), $id.' should not be bridged.');
        }

        $this->assertTrue($container->hasDefinition('access_control.voter.bridge.app.post_voter'));
    }

    /**
     * The core file stands alone while the bridge file only makes sense next to Security. Loading
     * them side by side is what catches a service id that does not exist.
     *
     * The hierarchy is left empty here, as in any application that has Security: it is declared
     * there and the bridge points our service at it, declaring both being refused.
     *
     * The container is then actually compiled and a decision actually made, because the closure
     * voter takes the manager, which takes the voters: deciding is what walks the tagged iterator
     * and proves the cycle is broken by its laziness rather than by luck.
     */
    public function testTheTwoConfigurationFilesFitTogether()
    {
        $container = new ContainerBuilder();
        $container->setParameter('access_control.default_strategy', 'permit_overrides');
        $container->setParameter('access_control.allow_if_equal_granted_denied', true);
        $container->setParameter('access_control.allow_if_all_abstain', false);
        $container->setParameter('access_control.role_prefix', 'ROLE_');
        $container->setParameter('access_control.role_hierarchy.roles', []);
        $container->register('event_dispatcher', EventDispatcher::class);
        $container->register('security.role_hierarchy', SecurityRoleHierarchy::class)->setArguments([['ROLE_ADMIN' => ['ROLE_USER']]]);
        $container->register('security.authentication.trust_resolver', AuthenticationTrustResolver::class);
        $container->register('security.token_storage', TokenStorage::class);
        $container->register('security.access.decision_manager');

        $loader = new PhpFileLoader($container, new FileLocator(\dirname(__DIR__, 4).'/src/symfony/src/Resources/config'));
        $loader->load('access_control.php');
        $loader->load('security_bridge.php');

        (new SecurityBridgePass())->process($container);
        $container->getDefinition('access_control.authorization_checker')->setPublic(true);
        $container->getDefinition('access_control.manager')->setPublic(true);
        $container->compile();

        $this->assertInstanceOf(AuthorizationCheckerAdapter::class, $container->get('access_control.authorization_checker'));

        $decision = $container->get('access_control.manager')->decide(new AccessRequest(null, 'ROLE_ADMIN'));

        $this->assertSame(DecisionVote::ACCESS_DENIED, $decision->decision);
    }

    private function containerWithAccessControl(): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->register('security.access.decision_manager');
        $container->register('access_control.manager');
        $container->register('access_control.access_decision_manager')->setArguments([null, null, null, 'permit_overrides']);
        $container->register('access_control.role_hierarchy', RoleHierarchy::class)->setArguments([[]]);
        $container->register('access_control.voter.role', RoleVoter::class)
            ->setArguments([new Reference('access_control.role_hierarchy'), 'ROLE_']);
        $container->register('access_control.voter.expression', ExpressionVoter::class)
            ->setArguments([null, null, null, new Reference('access_control.role_hierarchy')]);
        $container->register('access_control.voter.authenticated')->setArguments([null]);
        $container->register('access_control.strategy.majority', MajorityStrategy::class)->setArguments([true]);
        $container->setParameter('access_control.default_strategy', 'permit_overrides');
        $container->setParameter('access_control.allow_if_all_abstain', false);

        return $container;
    }
}
