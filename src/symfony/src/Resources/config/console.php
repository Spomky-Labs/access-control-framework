<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\Listener\ConsoleAccessPolicyListener;

return static function (ContainerConfigurator $container) {
    $container->services()
        // Nothing fills the token storage on the console, which is why the requester comes from a
        // provider rather than from Security. An application guarding commands points
        // access_control.requester_provider at a service account of its own.
        ->set('access_control.listener.console_access_policy', ConsoleAccessPolicyListener::class)
            ->args([
                service('access_control.requester_provider'),
                service('access_control.policy_evaluator'),
            ])
            ->tag('kernel.event_subscriber')
    ;
};
