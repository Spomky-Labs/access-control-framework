<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\AccessControlManager;
use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Handler\AccessPolicyHandler;
use AccessControl\Handler\AllHandler;
use AccessControl\Handler\AtLeastOneOfHandler;
use AccessControl\Listener\AccessDecisionLoggerListener;
use AccessControl\Listener\AccessPolicyListener;
use AccessControl\Requester\RequesterProviderInterface;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\RequesterBoundChecker;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\FirstApplicableStrategy;
use AccessControl\Strategy\MajorityStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use AccessControl\Voter\ClosureVoter;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleHierarchyInterface;
use AccessControl\Voter\RBAC\RoleVoter;

return static function (ContainerConfigurator $container) {
    $container->services()
        ->set('access_control.manager', AccessControlManager::class)
            ->args([
                tagged_iterator('access_control.strategy'),
                tagged_iterator('access_control.voter'),
                param('access_control.default_strategy'),
                service('event_dispatcher')->nullOnInvalid(),
                param('access_control.allow_if_all_abstain'),
            ])
            // The memoised voter support grows with the number of distinct attributes met, which
            // never ends in a worker.
            ->tag('kernel.reset', ['method' => 'reset'])
        ->alias(AccessControlManagerInterface::class, 'access_control.manager')

        // The four combining algorithms. Their names are those of XACML, and the correspondence
        // with Security is affirmative, unanimous, consensus and priority in that order.
        ->set('access_control.strategy.permit_overrides', PermitOverridesStrategy::class)
            ->tag('access_control.strategy')
        ->set('access_control.strategy.deny_overrides', DenyOverridesStrategy::class)
            ->tag('access_control.strategy')
        ->set('access_control.strategy.majority', MajorityStrategy::class)
            ->args([param('access_control.allow_if_equal_granted_denied')])
            ->tag('access_control.strategy')
        ->set('access_control.strategy.first_applicable', FirstApplicableStrategy::class)
            ->tag('access_control.strategy')

        // A yes or no question on behalf of whoever is asking right now. This is what a service or a
        // controller injects when it has to decide in the middle of its own work, the attribute and
        // the composites covering everything that can be declared up front.
        ->set('access_control.checker', RequesterBoundChecker::class)
            ->args([
                service('access_control.manager'),
                service('access_control.requester_provider'),
            ])
        ->alias(RequesterBoundChecker::class, 'access_control.checker')

        ->set('access_control.policy_evaluator', AccessPolicyEvaluator::class)
            ->args([
                tagged_iterator('access_control.policy_handler'),
                service('event_dispatcher')->nullOnInvalid(),
            ])

        ->set('access_control.policy_handler.access_policy', AccessPolicyHandler::class)
            ->args([service('access_control.manager')])
            ->tag('access_control.policy_handler')
        ->set('access_control.policy_handler.all', AllHandler::class)
            ->tag('access_control.policy_handler')
        ->set('access_control.policy_handler.at_least_one_of', AtLeastOneOfHandler::class)
            ->tag('access_control.policy_handler')

        // No requester by default: without one, a role is never held and only PUBLIC_ACCESS is
        // granted, which fails closed. The Security bridge points this alias at the token storage.
        ->set('access_control.requester_provider.static', StaticRequesterProvider::class)
        ->alias('access_control.requester_provider', 'access_control.requester_provider.static')
        ->alias(RequesterProviderInterface::class, 'access_control.requester_provider')

        // The component carries its own implementation, so that it works without Security at all.
        // With Security, the bridge aliases this onto security.role_hierarchy, whose contract now
        // extends ours, so a single object serves both stacks.
        ->set('access_control.role_hierarchy', RoleHierarchy::class)
            ->args([param('access_control.role_hierarchy.roles')])
        ->alias(RoleHierarchyInterface::class, 'access_control.role_hierarchy')

        // Registered without a trust resolver, which is what makes PUBLIC_ACCESS understood in an
        // application that has no Security. SecurityBridgePass fills the resolver in when there is
        // one, and the other authentication states become decidable from there on.
        ->set('access_control.voter.authenticated', AuthenticatedVoter::class)
            ->args([null])
            ->tag('access_control.voter')

        ->set('access_control.voter.role', RoleVoter::class)
            ->args([service('access_control.role_hierarchy'), param('access_control.role_prefix')])
            ->tag('access_control.voter')
        ->set('access_control.voter.closure', ClosureVoter::class)
            ->args([service('access_control.manager')])
            ->tag('access_control.voter')

        // Always registered, as Mailer does for its message logger: an integration test needs it,
        // and it is what the profiler collector will read. Reset between requests.
        ->set('access_control.decision_logger', AccessDecisionLoggerListener::class)
            // Walking the stack for the call site of every decision only pays for itself in debug.
            ->args([param('kernel.debug')])
            ->tag('kernel.event_subscriber')
            ->tag('kernel.reset', ['method' => 'reset'])

        ->set('access_control.listener.access_policy', AccessPolicyListener::class)
            ->args([
                service('access_control.requester_provider'),
                service('access_control.policy_evaluator'),
            ])
            ->tag('kernel.event_subscriber')
    ;
};
