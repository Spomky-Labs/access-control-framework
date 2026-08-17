<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\Bridge\Security\AccessDecisionManagerAdapter;
use AccessControl\Bridge\Security\AccessDeniedExceptionListener;
use AccessControl\Bridge\Security\AuthorizationCheckerAdapter;
use AccessControl\Requester\TokenStorageRequesterProvider;

return static function (ContainerConfigurator $container) {
    $container->services()
        // Overrides the empty provider the component falls back on, which grants nothing but
        // PUBLIC_ACCESS. On the console nothing fills the token storage, so a command keeps the
        // provider of its own that the application declares.
        ->set('access_control.requester_provider.token_storage', TokenStorageRequesterProvider::class)
            ->args([service('security.token_storage')])
        ->alias('access_control.requester_provider', 'access_control.requester_provider.token_storage')

        // The seam of the migration: everything that consumes AuthorizationCheckerInterface can be
        // pointed here without a line changed. Deliberately not aliased onto
        // security.authorization_checker, as swapping the whole authorization stack is a decision
        // an application makes, not a side effect of installing the component.
        // The widest seam: access_control rules, the authorization checker and therefore
        // #[IsGranted], the Twig functions and the workflow guards all end up here.
        ->set('access_control.access_decision_manager', AccessDecisionManagerAdapter::class)
            ->args([
                service('access_control.manager'),
                null,
                service('event_dispatcher')->nullOnInvalid(),
                // Overwritten by SecurityBridgePass with the word security.yaml used, when there is
                // one. Otherwise the algorithm was named on this component's key and that is the
                // word the application wrote.
                param('access_control.default_strategy'),
            ])

        ->set('access_control.authorization_checker', AuthorizationCheckerAdapter::class)
            ->args([
                service('access_control.manager'),
                service('access_control.requester_provider'),
            ])

        // A denial reported here is otherwise a plain 403 and an anonymous visitor is never offered
        // the login form, the firewall recognising Security's own exception alone.
        ->set('access_control.listener.access_denied_exception', AccessDeniedExceptionListener::class)
            ->tag('kernel.event_subscriber')
    ;
};
