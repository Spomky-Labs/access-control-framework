<?php

declare(strict_types=1);

namespace AccessControl\Listener;

use AccessControl\AccessEnvironment;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\DecisionVote;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Requester\RequesterProviderInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use function is_array;
use function is_object;
use function is_string;

/**
 * Denials are reported with the component's own exception: Security's exception listener catches
 * the marker interface, so a firewall still answers 403 or redirects to the login page, and an
 * application without one gets the 403 the exception carries.
 */
final readonly class AccessPolicyListener implements EventSubscriberInterface
{
    public function __construct(
        private RequesterProviderInterface $requesterProvider,
        private AccessPolicyEvaluator $accessPolicyEvaluator,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER_ARGUMENTS => ['onKernelControllerArguments', 20],
        ];
    }

    public function onKernelControllerArguments(ControllerArgumentsEvent $event): void
    {
        $context = new AccessPolicyContext(
            $this->requesterProvider->getRequester(),
            $event->getNamedArguments(),
            [
                AccessEnvironment::REQUEST => $event->getRequest(),
                'args' => $event->getArguments(),
            ],
            self::originOf($event->getController()),
        );

        foreach ($event->getAttributes() as $attributes) {
            foreach ($attributes as $attribute) {
                if (! $attribute instanceof AccessPolicyInterface) {
                    continue;
                }

                if ($this->accessPolicyEvaluator->evaluate($attribute, $context)->decision !== DecisionVote::ACCESS_DENIED) {
                    continue;
                }

                throw new AccessDeniedException($attribute->message ?? 'Access Denied.');
            }
        }
    }

    /**
     * Names the controller for the profiler, a flat log of decisions being unreadable without it.
     */
    private static function originOf(mixed $controller): string
    {
        return match (true) {
            is_string($controller) => $controller,
            is_array($controller) => (is_object($controller[0]) ? $controller[0]::class : $controller[0]) . '::' . $controller[1],
            default => get_debug_type($controller) . '::__invoke',
        };
    }
}
