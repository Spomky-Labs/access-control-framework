<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\Twig\AccessControlExtension;

return static function (ContainerConfigurator $container) {
    $container->services()
        // Removed by SecurityBridgePass when SecurityBundle registers its own: both publish an
        // is_granted() function, and Twig keeps whichever extension is initialised last without
        // saying a word about it.
        ->set('access_control.twig.extension', AccessControlExtension::class)
            ->args([
                service('access_control.checker'),
                service('access_control.manager'),
            ])
            ->tag('twig.extension')
    ;
};
