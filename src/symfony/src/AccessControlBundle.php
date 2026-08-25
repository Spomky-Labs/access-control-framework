<?php

declare(strict_types=1);

namespace AccessControl\Bundle;

use AccessControl\Bundle\DependencyInjection\Compiler\SecurityBridgePass;
use AccessControl\Bundle\DependencyInjection\Compiler\WorkflowGuardPass;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\Workflow\Event\GuardEvent;

/**
 * Registering this bundle is the opt-in: from there on the AccessControl component decides.
 *
 * @experimental
 */
class AccessControlBundle extends Bundle
{
    /**
     * Both passes are placed by priority rather than by registration order, which config/bundles.php
     * decides and this bundle does not.
     *
     * The bridge has to run before AddSecurityVotersPass, which bails out once
     * security.access.decision_manager is an alias. The workflow pass has to run before
     * WorkflowGuardListenerPass, registered at priority 0, which throws on the services of
     * SecurityBundle before it could ever be told they are not needed.
     */
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $container->addCompilerPass(new SecurityBridgePass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 100);

        if (class_exists(GuardEvent::class)) {
            $container->addCompilerPass(new WorkflowGuardPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 100);
        }
    }
}
