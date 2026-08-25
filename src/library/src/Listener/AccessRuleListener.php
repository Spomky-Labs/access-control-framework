<?php

declare(strict_types=1);

namespace AccessControl\Listener;

use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\DecisionVote;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Http\AccessRuleMapInterface;
use AccessControl\Requester\RequesterProviderInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Enforces the access rules declared for parts of the site, the counterpart of Security's
 * AccessListener for an application that has no firewall.
 *
 * It is a plain kernel listener rather than a firewall one, which is what makes it work with or
 * without Security. Denials are reported with the component's own exception, so a firewall still
 * answers 403 or redirects to the login page, and an application without one gets the 403 the
 * exception carries.
 *
 * @experimental
 */
final readonly class AccessRuleListener implements EventSubscriberInterface
{
    /**
     * Everything a rule decides is asked from the same place, so the origin says no more than that.
     * It is still worth recording: without it, a rule naming several roles reads in the profiler as
     * several unrelated questions.
     */
    private const string ORIGIN = 'access_control.rules';

    public function __construct(
        private AccessRuleMapInterface $accessRuleMap,
        private RequesterProviderInterface $requesterProvider,
        private AccessPolicyEvaluator $accessPolicyEvaluator,
    ) {
    }

    /**
     * Below Security's firewall, which runs at 8: a rule is only worth evaluating once the requester
     * is known. Above nothing else, so a denial short-circuits the controller.
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 7],
        ];
    }

    /**
     * The request is offered as an argument as well as in the environment, so that a rule can name
     * it as its subject the way a controller attribute names one of its own arguments. That is what
     * an allow_if expression reads when it calls request.getClientIp().
     */
    public function onKernelRequest(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $accessPolicy = $this->accessRuleMap->getRule($request)?->accessPolicy;

        if ($accessPolicy === null) {
            return;
        }

        $context = new AccessPolicyContext(
            $this->requesterProvider->getRequester(),
            [
                'request' => $request,
            ],
            [
                'request' => $request,
            ],
            self::ORIGIN,
        );

        if ($this->accessPolicyEvaluator->evaluate($accessPolicy, $context)->decision !== DecisionVote::ACCESS_DENIED) {
            return;
        }

        throw new AccessDeniedException($accessPolicy->message ?? 'Access Denied.');
    }
}
