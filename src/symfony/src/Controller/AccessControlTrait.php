<?php

declare(strict_types=1);

namespace AccessControl\Bundle\Controller;

use AccessControl\Exception\AccessDeniedException;
use AccessControl\RequesterBoundChecker;
use function func_get_args;

/**
 * Gives the access control helpers to a controller whose base class does not have them.
 *
 * FrameworkBundle's AbstractController and ControllerHelper only know Security: without it they
 * raise a LogicException telling the developer to install SecurityBundle, whichever other stack the
 * application registered. A controller extending them adds this trait and nothing else changes.
 *
 * A trait method wins over the one inherited from the parent class, so nothing else has to change:
 *
 *     class PostController extends AbstractController
 *     {
 *         use AccessControlTrait;
 *     }
 */
trait AccessControlTrait
{
    public static function getSubscribedServices(): array
    {
        $parent = get_parent_class(static::class);

        return [
            'access_control.checker' => '?' . RequesterBoundChecker::class,
        ]
            + ($parent ? $parent::getSubscribedServices() : []);
    }

    /**
     * Security answers first whenever it is there. Deciding the other way round would quietly walk
     * past a firewall's own checker, which is the one failure an access control helper must not
     * have. With AccessControlBundle registered the two reach the same voters anyway, its bridge
     * having pointed security.access.decision_manager at the component.
     */
    protected function isGranted(mixed $attribute, mixed $subject = null): bool
    {
        if ($this->container->has('security.authorization_checker')) {
            return $this->container->get('security.authorization_checker')
                ->isGranted($attribute, $subject);
        }

        return $this->container->get('access_control.checker')
            ->isGranted($attribute, $subject);
    }

    /**
     * With Security, the parent keeps answering: its exception carries the attributes, the subject
     * and the whole decision, which its exception listener and its error pages read. Without it,
     * the message is the one given and nothing else, an AccessControl denial keeping its diagnostic
     * out of the response on purpose.
     *
     * @throws AccessDeniedException
     */
    protected function denyAccessUnlessGranted(mixed $attribute, mixed $subject = null, string $message = 'Access Denied.'): void
    {
        if ($this->container->has('security.authorization_checker')) {
            parent::denyAccessUnlessGranted(...func_get_args());

            return;
        }

        if (! $this->isGranted($attribute, $subject)) {
            throw new AccessDeniedException($message);
        }
    }
}
