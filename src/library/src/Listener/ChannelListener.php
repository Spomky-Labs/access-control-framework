<?php

declare(strict_types=1);

namespace AccessControl\Listener;

use AccessControl\Http\AccessRuleMapInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Switches the HTTP protocol on the rules that require one, the counterpart of Security's
 * ChannelListener for an application that has no firewall.
 *
 * The channel travels with the rule because it is what a rule requires of the request, next to what
 * it requires of the requester. Enforcing it is not an access decision though, so no voter is
 * consulted and nothing reaches the decision log.
 */
final readonly class ChannelListener implements EventSubscriberInterface
{
    public function __construct(
        private AccessRuleMapInterface $accessRuleMap,
        private ?LoggerInterface $logger = null,
        private int $httpPort = 80,
        private int $httpsPort = 443,
    ) {
    }

    /**
     * Above the access rules, and above Security's firewall too: a request that is about to be
     * redirected is not worth authenticating, which is the order Security itself applies by running
     * its channel listener first of all the firewall listeners.
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 9],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $channel = $this->accessRuleMap->getRule($request)?->channel;

        if ($channel === 'https' && ! $request->isSecure()) {
            $this->logRedirectionToHttps($request);

            $event->setResponse($this->createRedirectResponse($request));

            return;
        }

        if ($channel === 'http' && $request->isSecure()) {
            $this->logger?->info('Redirecting to HTTP.');

            $event->setResponse($this->createRedirectResponse($request));
        }
    }

    private function logRedirectionToHttps(Request $request): void
    {
        if ($this->logger === null) {
            return;
        }

        if ($request->headers->get('X-Forwarded-Proto') === 'https') {
            $this->logger->info('Redirecting to HTTPS. ("X-Forwarded-Proto" header is set to "https" - did you set "trusted_proxies" correctly?)');
        } elseif (str_contains($request->headers->get('Forwarded', ''), 'proto=https')) {
            $this->logger->info('Redirecting to HTTPS. ("Forwarded" header is set to "proto=https" - did you set "trusted_proxies" correctly?)');
        } else {
            $this->logger->info('Redirecting to HTTPS.');
        }
    }

    private function createRedirectResponse(Request $request): RedirectResponse
    {
        $scheme = $request->isSecure() ? 'http' : 'https';

        if ($scheme === 'http' && $this->httpPort !== 80) {
            $port = ':' . $this->httpPort;
        } elseif ($scheme === 'https' && $this->httpsPort !== 443) {
            $port = ':' . $this->httpsPort;
        } else {
            $port = '';
        }

        $qs = $request->getQueryString();

        if ($qs !== null) {
            $qs = '?' . $qs;
        }

        return new RedirectResponse($scheme . '://' . $request->getHost() . $port . $request->getBaseUrl() . $request->getPathInfo() . $qs, 301);
    }
}
