<?php

declare(strict_types=1);

namespace AccessControl\Bundle\DependencyInjection\Compiler;

use AccessControl\Bridge\Workflow\GuardListener;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Workflow\EventListener\GuardListener as SecurityGuardListener;

/**
 * Lets a workflow guard run in an application that has no Security.
 *
 * Workflow's guard listener needs four services of SecurityBundle, and its own compiler pass refuses
 * to compile without them. This one hands the guards to a listener of this component instead, and
 * takes down the flag that pass reads, so it steps aside rather than throwing.
 *
 * It deliberately does nothing when Security is there. The guards of such an application already
 * reach this component, security.access.decision_manager being an alias to ours, so swapping the
 * listener would gain nothing and would cost the trust resolver an expression may name.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final class WorkflowGuardPass implements CompilerPassInterface
{
    /**
     * The four Workflow asks for, and the one that tells them apart: with SecurityBundle they are
     * all there, without it none is.
     */
    private const SECURITY_SERVICE = 'security.token_storage';

    /**
     * The flag is taken down last, so that a container where the swap did not happen still meets the
     * loud failure of WorkflowGuardListenerPass rather than compiling a guard nobody applies.
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter('workflow.has_guard_listeners') || $container->has(self::SECURITY_SERVICE)) {
            return;
        }

        foreach ($container->getDefinitions() as $definition) {
            if (SecurityGuardListener::class !== $definition->getClass()) {
                continue;
            }

            $definition->setClass(GuardListener::class);
            $definition->setArguments([
                $definition->getArgument(0),
                new Reference('access_control.workflow.voter.expression'),
                new Reference('access_control.requester_provider'),
            ]);
        }

        $container->getParameterBag()->remove('workflow.has_guard_listeners');
    }
}
