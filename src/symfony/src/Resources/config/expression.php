<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\ExpressionLanguage;
use AccessControl\Handler\WhenHandler;
use AccessControl\Voter\Expression\ExpressionVoter;

return static function (ContainerConfigurator $container) {
    $container->services()
        ->set('cache.access_control.expression_language')
            ->parent('cache.system')
            ->private()
            ->tag('cache.pool')

        ->set('access_control.expression_language', ExpressionLanguage::class)
            ->args([service('cache.access_control.expression_language')->nullOnInvalid()])

        ->set('access_control.voter.expression', ExpressionVoter::class)
            ->args([
                service('access_control.expression_language'),
                service('access_control.manager'),
                // Replaced by SecurityBridgePass, Security being the only one that has a trust resolver.
                null,
                service('access_control.role_hierarchy'),
            ])
            ->tag('access_control.voter')

        // The condition of a When composite reads the context the entry point handed over, so the
        // very same composite reads an HTTP method on the web and a console option elsewhere.
        ->set('access_control.policy_handler.when', WhenHandler::class)
            ->args([service('access_control.expression_language')])
            ->tag('access_control.policy_handler')
    ;
};
