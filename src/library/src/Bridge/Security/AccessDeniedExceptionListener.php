<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Security;

use AccessControl\Exception\AccessDeniedExceptionInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Says a denial of this component in the words the firewall already understands.
 *
 * The firewall is the only place that knows whether a denial ends in a 403 or in a redirection to
 * the login page, and it recognises Security's own exception alone. Left untranslated, a denial
 * reported here would reach the error page as a plain 403 and an anonymous visitor would never be
 * offered the login form, which is a visible regression against security.access_control.
 *
 * The translation happens here rather than by teaching Security about this component: Security must
 * keep working with no trace of AccessControl installed, so the knowledge goes in the direction
 * where the dependency is allowed to point.
 *
 * The chain of previous exceptions is walked as the firewall walks it, a template rendering being
 * enough to bury the denial under a wrapper. The outer layers are dropped on translation, which is
 * what the firewall does with them anyway.
 */
final class AccessDeniedExceptionListener implements EventSubscriberInterface
{
    /**
     * Just above the firewall's own exception listener, which registers itself at 1.
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::EXCEPTION => ['onKernelException', 2],
        ];
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $throwable = $event->getThrowable();

        do {
            if ($throwable instanceof AccessDeniedException) {
                return;
            }

            if ($throwable instanceof AccessDeniedExceptionInterface) {
                $event->setThrowable(new AccessDeniedException($throwable->getMessage(), $throwable));

                return;
            }
        } while (null !== $throwable = $throwable->getPrevious());
    }
}
