<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\DataCollector\AccessControlDataCollector;

return static function (ContainerConfigurator $container) {
    $container->services()
        // The logger is registered whether the profiler is or not, so the collector adds no
        // recording of its own: it only reads back and clones what is already there.
        ->set('data_collector.access_control', AccessControlDataCollector::class)
            ->args([
                service('access_control.decision_logger'),
                tagged_iterator('access_control.voter'),
                param('access_control.default_strategy'),
                param('.access_control.default_strategy_alias'),
                param('.access_control.integration'),
            ])
            ->tag('data_collector', [
                'template' => '@AccessControl/Collector/access_control.html.twig',
                'id' => 'access_control',
                'priority' => 265,
            ])
    ;
};
