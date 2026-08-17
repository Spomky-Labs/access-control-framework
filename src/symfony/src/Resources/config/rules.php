<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\Http\AccessRuleMap;
use AccessControl\Http\AccessRuleMapInterface;
use AccessControl\Listener\AccessRuleListener;
use AccessControl\Listener\ChannelListener;

return static function (ContainerConfigurator $container) {
    $container->services()
        // The rules themselves are filled in by the extension, one AccessRule per declared rule.
        ->set('access_control.rule_map', AccessRuleMap::class)
            ->args([abstract_arg('Access rules')])
        ->alias(AccessRuleMapInterface::class, 'access_control.rule_map')

        ->set('access_control.listener.access_rule', AccessRuleListener::class)
            ->args([
                service('access_control.rule_map'),
                service('access_control.requester_provider'),
                service('access_control.policy_evaluator'),
            ])
            ->tag('kernel.event_subscriber')

        // Removed by SecurityBridgePass when a firewall is present: security.channel_listener then
        // enforces the very same channels off security.access_map, and two redirections would fight.
        ->set('access_control.listener.channel', ChannelListener::class)
            ->args([
                service('access_control.rule_map'),
                service('logger')->nullOnInvalid(),
                param('request_listener.http_port'),
                param('request_listener.https_port'),
            ])
            ->tag('monolog.logger', ['channel' => 'access_control'])
            ->tag('kernel.event_subscriber')
    ;
};
