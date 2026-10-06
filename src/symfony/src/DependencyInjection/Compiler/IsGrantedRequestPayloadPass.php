<?php

declare(strict_types=1);

namespace AccessControl\Bundle\DependencyInjection\Compiler;

use Closure;
use ReflectionMethod;
use ReflectionParameter;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Http\EventListener\IsGrantedAttributeListener;
use function array_any;
use function class_exists;

/**
 * Lets #[IsGranted] vote on a request payload the way the installed Security does.
 *
 * Until the payload is mapped, a #[MapRequestPayload] argument holds the attribute itself. Since
 * Symfony 8.2, Security maps it first when the subject of #[IsGranted] reads it, so the voters get
 * the object. The component follows whatever the installed Security does, so the mapping is only
 * handed over when Security's own listener takes it too.
 *
 * The closure is lazy: without the Serializer the resolver is a service that throws as soon as it
 * is built, and #[IsGranted] has to keep working there.
 *
 * A compiler pass rather than the extension, as the resolver belongs to another bundle.
 */
final class IsGrantedRequestPayloadPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition('access_control.listener.is_granted') || ! $container->has('argument_resolver.request_payload') || ! self::securityMapsTheRequestPayload()) {
            return;
        }

        $container->getDefinition('access_control.listener.is_granted')
            ->setArgument(3, new Definition(Closure::class)
                ->setLazy(true)
                ->setFactory([Closure::class, 'fromCallable'])
                ->setArguments([[new Reference('argument_resolver.request_payload'), 'onKernelControllerArguments']]));
    }

    private static function securityMapsTheRequestPayload(): bool
    {
        return class_exists(IsGrantedAttributeListener::class) && array_any(
            new ReflectionMethod(IsGrantedAttributeListener::class, '__construct')->getParameters(),
            static fn (ReflectionParameter $parameter): bool => $parameter->name === 'mapRequestPayload',
        );
    }
}
