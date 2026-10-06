<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\DependencyInjection\Compiler;

use AccessControl\Bundle\DependencyInjection\Compiler\IsGrantedRequestPayloadPass;
use Closure;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionParameter;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Controller\ArgumentResolver\RequestPayloadValueResolver;
use Symfony\Component\Security\Http\EventListener\IsGrantedAttributeListener;
use function array_any;

final class IsGrantedRequestPayloadPassTest extends TestCase
{
    public function testTheListenerMapsTheRequestPayloadAsSecurityDoes(): void
    {
        if (! self::securityMapsTheRequestPayload()) {
            static::markTestSkipped('The installed Security does not map the request payload before #[IsGranted].');
        }

        $container = $this->container();

        new IsGrantedRequestPayloadPass()
            ->process($container);

        $mapRequestPayload = $container->getDefinition('access_control.listener.is_granted')
            ->getArgument(3);

        static::assertInstanceOf(Definition::class, $mapRequestPayload);
        static::assertTrue($mapRequestPayload->isLazy());
        static::assertSame([Closure::class, 'fromCallable'], $mapRequestPayload->getFactory());
        static::assertEquals([[new Reference('argument_resolver.request_payload'), 'onKernelControllerArguments']], $mapRequestPayload->getArguments());
    }

    public function testNothingChangesWhileSecurityDoesNotMapTheRequestPayload(): void
    {
        if (self::securityMapsTheRequestPayload()) {
            static::markTestSkipped('The installed Security maps the request payload before #[IsGranted].');
        }

        $container = $this->container();

        new IsGrantedRequestPayloadPass()
            ->process($container);

        static::assertCount(3, $container->getDefinition('access_control.listener.is_granted')->getArguments());
    }

    public function testNothingChangesWithoutTheRequestPayloadResolver(): void
    {
        $container = $this->container();
        $container->removeDefinition('argument_resolver.request_payload');

        new IsGrantedRequestPayloadPass()
            ->process($container);

        static::assertCount(3, $container->getDefinition('access_control.listener.is_granted')->getArguments());
    }

    private function container(): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setDefinition('access_control.listener.is_granted', new Definition(null, [
            new Reference('access_control.requester_provider'),
            new Reference('access_control.policy_evaluator'),
            null,
        ]));
        $container->setDefinition('argument_resolver.request_payload', new Definition(RequestPayloadValueResolver::class));

        return $container;
    }

    private static function securityMapsTheRequestPayload(): bool
    {
        return array_any(new ReflectionMethod(IsGrantedAttributeListener::class, '__construct')->getParameters(), static fn (ReflectionParameter $parameter): bool => $parameter->name === 'mapRequestPayload');
    }
}
