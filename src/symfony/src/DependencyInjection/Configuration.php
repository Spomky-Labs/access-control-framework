<?php

declare(strict_types=1);

namespace AccessControl\Bundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * There is no enabled flag: registering the bundle is what turns the component on.
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('access_control');

        $treeBuilder->getRootNode()
            ->children()
            ->enumNode('default_strategy')
            ->info('The combining algorithm applied when a request names none. The XACML names of the Security strategies are, in order, affirmative, unanimous, consensus and priority.')
            ->values(['permit_overrides', 'deny_overrides', 'majority', 'first_applicable'])
            ->defaultValue('permit_overrides')
            ->end()
            ->booleanNode('allow_if_all_abstain')
            ->info('What to answer when no voter had anything to say. An application that has Security declares it under security.access_decision_manager instead.')
            ->defaultFalse()
            ->end()
            ->booleanNode('allow_if_equal_granted_denied')
            ->info('Whether the majority strategy grants access when both sides weigh the same.')
            ->defaultTrue()
            ->end()
            ->scalarNode('role_prefix')
            ->info('The prefix an attribute must carry to be read as a role.')
            ->defaultValue('ROLE_')
            ->end()
            ->end()
        ;

        $this->addRoleHierarchySection($treeBuilder->getRootNode());
        $this->addRulesSection($treeBuilder->getRootNode());

        return $treeBuilder;
    }

    /**
     * The shape is that of security.role_hierarchy, down to the normalisations, so that a hierarchy
     * reads the same whichever key declares it and moves across without being rewritten.
     *
     * An application that has Security keeps declaring it there, the bridge pointing this
     * component's service at security.role_hierarchy. This key is for the ones that have no
     * Security to declare it in.
     */
    private function addRoleHierarchySection(ArrayNodeDefinition $rootNode): void
    {
        $rootNode
            ->children()
            ->arrayNode('role_hierarchy', 'role')
            ->info('Roles reached by holding another one, declared here only when the application has no Security.')
            ->useAttributeAsKey('id')
            ->prototype('array')
            ->performNoDeepMerging()
            ->beforeNormalization()
            ->ifString()
            ->then(static fn ($v) => preg_split('/\s*,\s*/', $v))
            ->end()
            ->prototype('scalar')
            ->end()
            ->end()
            ->end()
            ->end()
        ;
    }

    /**
     * The options are those of security.access_control, so that a rule reads the same whether the
     * application has a firewall or not. The key is "rules" rather than "access_control", which
     * would have read as access_control.access_control under the component's own root key.
     */
    private function addRulesSection(ArrayNodeDefinition $rootNode): void
    {
        $rootNode
            ->children()
            ->arrayNode('rules', 'rule')
            ->info('Access rules for parts of the site, matched in declaration order, the first match winning.')
            ->cannotBeOverwritten()
            ->prototype('array')
            ->children()
            ->scalarNode('request_matcher')
            ->defaultNull()
            ->end()
            ->scalarNode('requires_channel')
            ->defaultNull()
            ->end()
            ->scalarNode('path')
            ->defaultNull()
            ->info('Use the urldecoded format.')
            ->example('^/path to resource/')
            ->end()
            ->scalarNode('host')
            ->defaultNull()
            ->end()
            ->integerNode('port')
            ->defaultNull()
            ->end()
            ->arrayNode('ips', 'ip')
            ->acceptAndWrap(['string'])
            ->prototype('scalar')
            ->end()
            ->end()
            ->arrayNode('attributes', 'attribute')
            ->useAttributeAsKey('key')
            ->prototype('scalar')
            ->end()
            ->end()
            ->scalarNode('route')
            ->defaultNull()
            ->end()
            ->arrayNode('methods', 'method')
            ->beforeNormalization()
            ->ifString()
            ->then(static fn ($v) => preg_split('/\s*,\s*/', $v))
            ->end()
            ->prototype('scalar')
            ->end()
            ->end()
            ->scalarNode('allow_if')
            ->defaultNull()
            ->end()
            ->arrayNode('roles', 'role')
            ->beforeNormalization()
            ->ifString()
            ->then(static fn ($v) => preg_split('/\s*,\s*/', $v))
            ->end()
            ->prototype('scalar')
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
        ;
    }
}
