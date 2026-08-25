<?php

declare(strict_types=1);

namespace AccessControl\Bundle\DependencyInjection\Compiler;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\Bridge\Security\RoleHierarchyAdapter;
use AccessControl\Bridge\Security\StrategyAdapter;
use AccessControl\Bridge\Security\VoterAdapter;
use AccessControl\Bundle\Twig\SecurityExtensionWithoutAuthorization;
use AccessControl\Http\AccessRule;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Argument\IteratorArgument;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Core\Authorization\Strategy\AffirmativeStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\ConsensusStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\PriorityStrategy;
use Symfony\Component\Security\Core\Authorization\Strategy\UnanimousStrategy;
use function count;
use function dirname;
use function in_array;
use function sprintf;

/**
 * Hands the AccessControl voters what only Security has, then puts the component in charge.
 *
 * The extension registers the expression voter with a null trust resolver, which is optional by
 * design so that the component works without Security at all. This is where it is filled in.
 *
 * A compiler pass rather than the extension, as the definitions belong to another bundle.
 */
class SecurityBridgePass implements CompilerPassInterface
{
    /**
     * The voters Security ships, which the component replaces with native ones. Everything else
     * tagged security.voter belongs to the application and is bridged rather than dropped.
     */
    private const array SECURITY_OWN_VOTERS = [
        'security.access.simple_role_voter',
        'security.access.role_hierarchy_voter',
        'security.access.authenticated_voter',
        'security.access.expression_voter',
        'security.access.closure_voter',
    ];

    /**
     * The four combining algorithms Symfony ships, under the names each stack gives them. The
     * component keeps the XACML names on purpose, so the correspondence has to live somewhere.
     */
    private const array STRATEGIES = [
        AffirmativeStrategy::class => 'permit_overrides',
        UnanimousStrategy::class => 'deny_overrides',
        ConsensusStrategy::class => 'majority',
        PriorityStrategy::class => 'first_applicable',
    ];

    /**
     * The name security.yaml gives each of them, which is the word the developer wrote and the one
     * the profiler owes them.
     */
    private const array SECURITY_STRATEGY_NAMES = [
        'affirmative' => AffirmativeStrategy::class,
        'unanimous' => UnanimousStrategy::class,
        'consensus' => ConsensusStrategy::class,
        'priority' => PriorityStrategy::class,
    ];

    /**
     * The extension registers these on the strength of SecurityBundle being installed, which is not
     * the same as it being registered.
     */
    private const array BRIDGE_SERVICES = [
        'access_control.requester_provider.token_storage',
        'access_control.access_decision_manager',
        'access_control.authorization_checker',
        'access_control.listener.access_denied_exception',
    ];

    /**
     * Three outcomes, told apart by two questions asked in this order.
     *
     * SecurityBundle registered at all, asked with has() and not hasDefinition(): an application
     * that named a decision manager of its own leaves an alias here rather than a definition, and
     * reading that as "SecurityBundle is not registered" took the whole bridge out. Measured, with
     * a firewall and a logged in user, every requester on this side became anonymous.
     *
     * Then whether the decision manager is still SecurityBundle's to point elsewhere. An
     * application that named one of its own has chosen who answers, and this bundle takes over
     * nothing: routing #[IsGranted] or a template through the component would hand its questions to
     * an engine it did not pick. Everything before that point still applies, the component's own
     * entry points needing the requester and the hierarchy either way.
     *
     * The alias set last is the opt-in itself: from there on the component decides, and everything
     * that asks Security follows, without a line changing in security.yaml.
     *
     * The trust resolver handed to the authenticated voter is what makes every authentication state
     * decidable; without one that voter only understands PUBLIC_ACCESS, which is all an application
     * without a firewall can mean.
     */
    public function process(ContainerBuilder $container): void
    {
        if (! $container->has('security.access.decision_manager')) {
            $this->removeTheBridge($container);

            return;
        }

        $this->note($container, 'security_bundle', true);
        $this->shareTheRules($container);
        $this->shareTheRoleHierarchy($container);

        if ($container->hasDefinition('access_control.voter.expression')) {
            $container->getDefinition('access_control.voter.expression')
                ->replaceArgument(2, new Reference('security.authentication.trust_resolver'));
        }

        $container->getDefinition('access_control.voter.authenticated')
            ->replaceArgument(0, new Reference('security.authentication.trust_resolver'));

        $this->bridgeApplicationVoters($container);

        if (! $container->hasDefinition('security.access.decision_manager')) {
            $this->note($container, 'decisions', 'application');
            $this->note($container, 'is_granted', $container->hasDefinition('controller.is_granted_attribute_listener') ? 'security' : 'none');
            $this->note($container, 'twig', $container->hasDefinition('twig.extension.security') ? 'security' : 'none');

            return;
        }

        $this->shareTheDecisionStrategy($container);
        $this->takeOverTheTwigFunctions($container);
        $this->takeOverTheIsGrantedAttribute($container);
        $this->note($container, 'decisions', 'component');
        $container->setAlias('security.access.decision_manager', 'access_control.access_decision_manager');
    }

    /**
     * The extension registers the bridge on the strength of SecurityBundle being installed, which is
     * not the same as it being registered. Without a firewall it has to take itself back out.
     *
     * Only the alias this bundle set is undone. An application that pointed the provider at one of
     * its own has said what it wants, and putting the empty provider back would silently leave
     * every requester anonymous.
     */
    private function removeTheBridge(ContainerBuilder $container): void
    {
        foreach (self::BRIDGE_SERVICES as $id) {
            $container->removeDefinition($id);
        }

        if ($container->hasAlias('access_control.requester_provider')
            && (string) $container->getAlias('access_control.requester_provider') === 'access_control.requester_provider.token_storage'
        ) {
            $container->setAlias('access_control.requester_provider', 'access_control.requester_provider.static');
        }
    }

    /**
     * Both extensions publish an is_granted() function. Measured: Twig raises nothing, it keeps
     * whichever extension was initialised last, so the answer would depend on the order of
     * config/bundles.php. Registering this bundle is the opt-in, so the two functions this
     * component answers become its own, and Security's extension is left publishing the rest.
     */
    private function takeOverTheTwigFunctions(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition('twig.extension.security') || ! $container->hasDefinition('access_control.twig.extension')) {
            return;
        }

        $container->setDefinition('access_control.twig.extension.security', $container->getDefinition('twig.extension.security'))
            ->clearTag('twig.extension');

        $container->setDefinition('twig.extension.security', new Definition(SecurityExtensionWithoutAuthorization::class))
            ->setArguments([new Reference('access_control.twig.extension.security')])
            ->addTag('twig.extension');
    }

    /**
     * Two listeners would decide the same attribute and the requester would be asked twice for one
     * question, which the profiler would show as two. The component's is the one that answers, its
     * denial reaching the firewall through the bridge listener.
     */
    private function takeOverTheIsGrantedAttribute(ContainerBuilder $container): void
    {
        if ($container->hasDefinition('controller.is_granted_attribute_listener') && $container->hasDefinition('access_control.listener.is_granted')) {
            $container->removeDefinition('controller.is_granted_attribute_listener');
        }
    }

    /**
     * The combining algorithm of security.access_decision_manager becomes the component's.
     *
     * Without this the application that chose "unanimous" silently falls back to this component's
     * default, permit_overrides, and starts granting what it used to refuse. Measured on three of
     * the four strategies plus allow_if_equal_granted_denied: installing the bundle loosened access.
     *
     * Read from the definition rather than from the configuration: SecurityExtension turns the
     * chosen algorithm into a plain Definition of one of four classes, with allow_if_all_abstain in
     * argument 0 and allow_if_equal_granted_denied in argument 1, so the class alone says which one
     * it is. An application that named an algorithm on this component's own key has spoken later
     * and keeps it, but naming two different ones is a contradiction rather than a precedence.
     *
     * An algorithm the application wrote itself arrives as a Reference and is wrapped rather than
     * translated. What is reported to a template is then the algorithm's own class, which is what
     * Security reported too through get_debug_type(); naming the wrapper would tell a template about
     * this bridge rather than about the algorithm it asked for. Known divergence, and the only one:
     * an algorithm that is Stringable was reported by its string, which cannot be read from a
     * definition. The four Symfony ships are, but they are named through the strategy key.
     *
     * The alias exists because the developer wrote "unanimous" and the panel would otherwise show
     * "deny_overrides", a translation they have to make in their head during the very period they
     * are unsure what changed.
     *
     * The all abstain rule is carried by every strategy of Security and by the manager here, one
     * setting being obeyed by every entry point rather than by the ones that remembered to pass it.
     */
    private function shareTheDecisionStrategy(ContainerBuilder $container): void
    {
        $manager = $container->getDefinition('security.access.decision_manager');

        if (! $container->hasParameter('access_control.default_strategy') || null === $strategy = $manager->getArguments()[1] ?? null) {
            return;
        }

        if ($strategy instanceof Reference) {
            $container->register('access_control.strategy.security', StrategyAdapter::class)
                ->setArguments([$strategy, 'security'])
                ->addTag('access_control.strategy');

            $this->reportTheStrategyAs($container, $container->has($id = (string) $strategy) ? $container->findDefinition($id)->getClass() : null);
            $this->useStrategy($container, 'security', 'security.access_decision_manager.strategy_service');

            return;
        }

        if (! $strategy instanceof Definition || null === $name = self::STRATEGIES[$strategy->getClass()] ?? null) {
            return;
        }

        $alias = array_search($strategy->getClass(), self::SECURITY_STRATEGY_NAMES, true) ?: null;

        if ($container->hasParameter('.access_control.default_strategy_alias')) {
            $container->setParameter('.access_control.default_strategy_alias', $alias);
        }

        $this->reportTheStrategyAs($container, $alias);
        $this->useAllAbstainRule($container, (bool) ($strategy->getArguments()[0] ?? false));

        if ($strategy->getClass() === ConsensusStrategy::class && isset($strategy->getArguments()[1])) {
            $container->getDefinition('access_control.strategy.majority')
                ->setArgument(0, $strategy->getArguments()[1]);
        }

        $this->useStrategy($container, $name, 'security.access_decision_manager.strategy');
    }

    /**
     * Which of the two stacks enforces the URL rules, all of them, including the channel.
     *
     * The two keys declare the same eleven options and mean the same thing, but they are not
     * enforced in the same place: a rule of security.access_control is a link in the chain of each
     * firewall, one of access_control.rules is a listener of the kernel. Declaring both is therefore
     * the union of the two, the firewall answering first, and a rule moved from one key to the other
     * without the original being deleted quietly yields the intersection of the two permissions.
     * Measured on an application carrying both: a path covered by each answered 403 where the
     * firewall alone granted. So one key holds them all, and the block moves whole.
     *
     * Whichever key that is decides the channel too. Stepping aside on the mere existence of the
     * firewall's channel listener was a silent hole: measured, requires_channel declared here with
     * SecurityBundle registered served the page in the clear, ours removed and Security's with an
     * empty map to enforce.
     */
    private function shareTheRules(ContainerBuilder $container): void
    {
        if (! $this->securityHasRules($container)) {
            return;
        }

        if ($container->hasDefinition('access_control.rule_map')) {
            throw new InvalidArgumentException('Access rules are declared under both "security.access_control" and "access_control.rules", which is the union of the two rather than one of them. Declare them all on one key.');
        }

        $this->takeOverTheRulesOfSecurity($container);
    }

    /**
     * The rules of security.access_control, enforced by this component rather than by the firewall.
     *
     * Read from the map SecurityExtension filled rather than from the configuration, which this
     * bundle's extension is not allowed to see. Each call carries the matcher Security already
     * built, so the whole matching side, path, host, port, ips, methods, route, attributes and a
     * request_matcher of the application's own, is carried across without being reproduced.
     *
     * Only the attributes are translated, into the very shape the component's own key produces: one
     * AccessPolicy per attribute, the request as its subject, and AtLeastOneOf above them, which is
     * what "roles: [A, B]" has always meant on either key.
     *
     * The services of the rules are loaded here rather than by the extension, which only knows about
     * this component's own key and has nothing to register when the rules are declared on Security's.
     */
    private function takeOverTheRulesOfSecurity(ContainerBuilder $container): void
    {
        $this->note($container, 'rules', 'security');
        $rules = [];
        $requiresChannel = false;

        foreach ($container->getDefinition('security.access_map')->getMethodCalls() as [$method, $arguments]) {
            if ($method !== 'add') {
                continue;
            }

            [$matcher, $attributes, $channel] = $arguments + [null, [], null];
            $rules[] = new Definition(AccessRule::class, [$matcher, self::policyOf($attributes), $channel]);
            $requiresChannel = $requiresChannel || $channel !== null;
        }

        new PhpFileLoader($container, new FileLocator(dirname(__DIR__, 2) . '/Resources/config'))->load('rules.php');

        $container->getDefinition('access_control.rule_map')
            ->replaceArgument(0, $rules);

        if (! $requiresChannel) {
            $container->removeDefinition('access_control.listener.channel');
        }

        $this->takeTheRulesOutOfTheFirewalls($container);
    }

    /**
     * @param list<string|Reference> $attributes the roles of the rule, plus its allow_if expression
     *                                           as a reference to the service Security built for it
     */
    private static function policyOf(array $attributes): ?Definition
    {
        $policies = [];

        foreach ($attributes as $attribute) {
            $policies[] = new Definition(AccessPolicy::class, [$attribute, new Definition(Argument::class, ['request'])]);
        }

        return match (count($policies)) {
            0 => null,
            1 => $policies[0],
            default => new Definition(AtLeastOneOf::class, [$policies]),
        };
    }

    /**
     * Both links are pulled out of every firewall, the rules and the channel going together: leaving
     * either would answer the same rule twice.
     *
     * The order is preserved rather than changed: the firewall runs at kernel.request priority 8 and
     * this component's rule listener at 7, so a rule is still enforced after authentication and
     * before the controller, exactly where it was.
     */
    private function takeTheRulesOutOfTheFirewalls(ContainerBuilder $container): void
    {
        if (! $container->hasParameter('security.firewalls')) {
            return;
        }

        foreach ($container->getParameter('security.firewalls') as $name) {
            if (! $container->hasDefinition($id = 'security.firewall.map.context.' . $name)) {
                continue;
            }

            $context = $container->getDefinition($id);
            $listeners = $context->getArgument(0);

            $context->replaceArgument(0, new IteratorArgument(array_values(array_filter(
                $listeners instanceof IteratorArgument ? $listeners->getValues() : $listeners,
                static fn ($listener) => ! in_array((string) $listener, ['security.access_listener', 'security.channel_listener'], true),
            ))));
        }
    }

    private function securityHasRules(ContainerBuilder $container): bool
    {
        if (! $container->hasDefinition('security.access_map')) {
            return false;
        }

        foreach ($container->getDefinition('security.access_map')->getMethodCalls() as [$method]) {
            if ($method === 'add') {
                return true;
            }
        }

        return false;
    }

    /**
     * The same treatment as the algorithm itself: security.yaml wins where it speaks, an explicit
     * choice on this component's key is honoured where Security is silent, and naming both is a
     * contradiction rather than a precedence.
     */
    private function useAllAbstainRule(ContainerBuilder $container, bool $allowIfAllAbstain): void
    {
        if (! $container->hasParameter('access_control.allow_if_all_abstain')) {
            return;
        }

        $configured = $container->hasParameter('.access_control.all_abstain_configured')
            && $container->getParameter('.access_control.all_abstain_configured');

        if ($configured && $allowIfAllAbstain !== $container->getParameter('access_control.allow_if_all_abstain')) {
            throw new InvalidArgumentException('The "security.access_decision_manager.allow_if_all_abstain" option and "access_control.allow_if_all_abstain" say the opposite of one another. Declare it once.');
        }

        $container->setParameter('access_control.allow_if_all_abstain', $allowIfAllAbstain);
    }

    /**
     * The word access_decision() hands back to a template, which Security filled from the algorithm
     * object itself and which the adapter cannot guess: it knows the algorithm to run, not the name
     * under which the application asked for it.
     */
    private function reportTheStrategyAs(ContainerBuilder $container, ?string $name): void
    {
        if ($name !== null) {
            $container->getDefinition('access_control.access_decision_manager')
                ->replaceArgument(3, $name);
        }
    }

    /**
     * @param string $option the key of security.yaml the name comes from, so that a contradiction
     *                       names both sides rather than the winner alone
     */
    private function useStrategy(ContainerBuilder $container, string $name, string $option): void
    {
        $configured = $container->hasParameter('.access_control.strategy_configured')
            && $container->getParameter('.access_control.strategy_configured');

        if ($configured && $name !== $container->getParameter('access_control.default_strategy')) {
            throw new InvalidArgumentException(sprintf('The "%s" option and "access_control.default_strategy" name two different combining algorithms, "%s" and "%s". Declare it once.', $option, $name, $container->getParameter('access_control.default_strategy')));
        }

        $container->setParameter('access_control.default_strategy', $name);
    }

    /**
     * Both stacks held their own hierarchy, built from the same security.role_hierarchy
     * configuration, so one object serves both and an application that replaced
     * security.role_hierarchy with its own is honoured here too.
     *
     * Through an adapter and not an alias, Security's hierarchy not implementing the component's
     * contract: neither component knows the other's, and the one that may hold the knowledge is
     * this one.
     *
     * Since the alias below wins, a hierarchy declared on this component's own key would be built
     * and then never consulted, which is a configuration that silently does nothing.
     */
    private function shareTheRoleHierarchy(ContainerBuilder $container): void
    {
        if (! $container->has('security.role_hierarchy') || ! $container->has('access_control.role_hierarchy')) {
            return;
        }

        if ($container->hasParameter('access_control.role_hierarchy.roles') && $container->getParameter('access_control.role_hierarchy.roles')) {
            throw new InvalidArgumentException('The "access_control.role_hierarchy" option is for an application that has no Security. Declare the hierarchy under "security.role_hierarchy" alone, which this component reads.');
        }

        $container->register('access_control.role_hierarchy.security', RoleHierarchyAdapter::class)
            ->setArguments([new Reference('security.role_hierarchy')]);

        $container->setAlias('access_control.role_hierarchy', 'access_control.role_hierarchy.security');
        $this->note($container, 'role_hierarchy', 'security');
    }

    /**
     * Every application has voters extending Security's Voter. Left alone, they would stop being
     * consulted the day the decision manager is pointed at the component, with no error and no
     * deprecation: access rules that quietly no longer apply. Each one is therefore wrapped and
     * registered in the component's own collection, keeping the priority it was tagged with.
     */
    private function bridgeApplicationVoters(ContainerBuilder $container): void
    {
        $bridged = 0;

        foreach ($container->findTaggedServiceIds('security.voter') as $id => $tags) {
            if (in_array($id, self::SECURITY_OWN_VOTERS, true)) {
                continue;
            }

            $container->register('access_control.voter.bridge.' . $id, VoterAdapter::class)
                ->setArguments([new Reference($id)])
                ->addTag('access_control.voter', $tags[0] ?? []);

            ++$bridged;
        }

        $this->note($container, 'bridged_voters', $bridged);
    }

    /**
     * Records what this pass decided, for the profiler to show. Two applications carrying the same
     * two bundles can end up answering their questions with different engines, and nothing else
     * says which one you are looking at.
     */
    private function note(ContainerBuilder $container, string $key, mixed $value): void
    {
        if (! $container->hasParameter('.access_control.integration')) {
            return;
        }

        $container->setParameter('.access_control.integration', [
            $key => $value,
        ] + $container->getParameter('.access_control.integration'));
    }
}
