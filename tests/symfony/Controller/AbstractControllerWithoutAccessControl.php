<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Controller;

use Psr\Container\ContainerInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Contracts\Service\ServiceSubscriberInterface;

/**
 * AbstractController as it stands wherever the component and the bundle are not part of Symfony:
 * it knows Security and nothing else, and raises when there is none.
 *
 * Faithful to the shape that matters, down to func_num_args() deciding whether the message of the
 * decision or the one given wins, which the trait has to forward.
 */
abstract class AbstractControllerWithoutAccessControl implements ServiceSubscriberInterface
{
    protected ContainerInterface $container;

    public function setContainer(ContainerInterface $container): void
    {
        $this->container = $container;
    }

    public static function getSubscribedServices(): array
    {
        return [
            'security.authorization_checker' => '?'.AuthorizationCheckerInterface::class,
        ];
    }

    protected function isGranted(mixed $attribute, mixed $subject = null): bool
    {
        if (!$this->container->has('security.authorization_checker')) {
            throw new \LogicException('The SecurityBundle is not registered in your application. Try running "composer require symfony/security-bundle".');
        }

        return $this->container->get('security.authorization_checker')->isGranted($attribute, $subject);
    }

    protected function denyAccessUnlessGranted(mixed $attribute, mixed $subject = null, string $message = 'Access Denied.'): void
    {
        if ($this->isGranted($attribute, $subject)) {
            return;
        }

        $e = new AccessDeniedException(3 > \func_num_args() ? 'Denied by Security.' : $message);
        $e->setAttributes([$attribute]);
        $e->setSubject($subject);

        throw $e;
    }
}
