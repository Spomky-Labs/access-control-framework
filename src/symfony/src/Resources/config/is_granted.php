<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\Bridge\Security\IsGrantedListener;

return static function (ContainerConfigurator $container) {
    $container->services()
        // Removed by SecurityBridgePass when SecurityBundle registers its own listener for the
        // attribute. Without a firewall nobody reads #[IsGranted] at all, and a controller that was
        // guarded answers 200 without a word, which is what this closes.
        ->set('access_control.listener.is_granted', IsGrantedListener::class)
            ->args([
                service('access_control.requester_provider'),
                service('access_control.policy_evaluator'),
                service('access_control.expression_language')->nullOnInvalid(),
            ])
            ->tag('kernel.event_subscriber')
    ;
};
