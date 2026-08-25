<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use AccessControl\Bridge\Security\AccessDeniedExceptionListener;
use AccessControl\Exception\AccessDeniedException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException as SecurityAccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Firewall\ExceptionListener;
use Symfony\Component\Security\Http\HttpUtils;
use Throwable;

/**
 * Security recognises its own denial alone and must keep doing so, this component being nowhere in
 * its dependencies. The translation happens here instead, and what it buys is the firewall's whole
 * behaviour: the login form offered to a visitor who has not authenticated yet, rather than a bare
 * 403 telling them nothing.
 */
final class AccessDeniedExceptionListenerTest extends TestCase
{
    /**
     * The firewall registers its own listener at 1, so this one has to come first or there is
     * nothing left to translate.
     */
    public function testItRunsBeforeTheFirewall(): void
    {
        static::assertSame(['onKernelException', 2], AccessDeniedExceptionListener::getSubscribedEvents()[KernelEvents::EXCEPTION]);
    }

    public function testADenialOfThisComponentIsSaidAgainInSecurityTerms(): void
    {
        $event = $this->createEvent($denial = new AccessDeniedException('Nope.'));

        new AccessDeniedExceptionListener()
            ->onKernelException($event);

        $throwable = $event->getThrowable();

        static::assertInstanceOf(SecurityAccessDeniedException::class, $throwable);
        static::assertSame('Nope.', $throwable->getMessage());
        static::assertSame($denial, $throwable->getPrevious());
    }

    public function testSecuritysOwnDenialIsLeftAlone(): void
    {
        $event = $this->createEvent($denial = new SecurityAccessDeniedException('Nope.'));

        new AccessDeniedExceptionListener()
            ->onKernelException($event);

        static::assertSame($denial, $event->getThrowable());
    }

    public function testAnythingElseIsLeftAlone(): void
    {
        $event = $this->createEvent($failure = new RuntimeException('Boom.'));

        new AccessDeniedExceptionListener()
            ->onKernelException($event);

        static::assertSame($failure, $event->getThrowable());
    }

    /**
     * Rendering a template is enough to bury the denial, Twig wrapping whatever a function throws.
     * The firewall walks the chain of previous exceptions for that very reason, and so does this.
     */
    public function testADenialBuriedUnderAWrapperIsStillFound(): void
    {
        $event = $this->createEvent(new RuntimeException('An exception has been thrown during the rendering of a template.', 0, $denial = new AccessDeniedException('Nope.')));

        new AccessDeniedExceptionListener()
            ->onKernelException($event);

        static::assertSame($denial, $event->getThrowable()->getPrevious());
    }

    /**
     * The point of the whole class, through the real path: both listeners on one dispatcher, at the
     * priorities they declare, and the firewall answering as it answers its own denials.
     */
    public function testAVisitorWhoHasNotAuthenticatedIsOfferedTheLoginForm(): void
    {
        $response = $this->dispatch(new AccessDeniedException('Nope.'), null);

        static::assertSame('the entry point', $response?->getContent());
    }

    public function testTheSameDenialReportedBySecurityAnswersAlike(): void
    {
        static::assertSame(
            $this->dispatch(new SecurityAccessDeniedException('Nope.'), null)?->getContent(),
            $this->dispatch(new AccessDeniedException('Nope.'), null)?->getContent(),
        );
    }

    /**
     * A fully authenticated requester is refused rather than sent to the login form, and without an
     * access denied handler the firewall leaves the 403 to the error page.
     */
    public function testAnAuthenticatedRequesterIsRefused(): void
    {
        $token = new UsernamePasswordToken(new InMemoryUser('alice', null), 'main', ['ROLE_USER']);

        static::assertNull($this->dispatch(new AccessDeniedException('Nope.'), $token));
    }

    /**
     * Nothing of the firewall is short circuited: an authentication failure is still the firewall's
     * to handle, and this listener steps aside on anything that is not a denial.
     */
    public function testAnAuthenticationFailureStillReachesTheFirewall(): void
    {
        $response = $this->dispatch(new AuthenticationException('Who are you?'), null);

        static::assertSame('the entry point', $response?->getContent());
    }

    private function dispatch(Throwable $throwable, ?TokenInterface $token): ?Response
    {
        $tokenStorage = new TokenStorage();
        if ($token !== null) {
            $tokenStorage->setToken($token);
        }

        $entryPoint = new class() implements AuthenticationEntryPointInterface {
            public function start(Request $request, ?AuthenticationException $authException = null): Response
            {
                return new Response('the entry point');
            }
        };

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new AccessDeniedExceptionListener());
        new ExceptionListener($tokenStorage, new AuthenticationTrustResolver(), new HttpUtils(), 'main', $entryPoint)
            ->register($dispatcher);

        $dispatcher->dispatch($event = $this->createEvent($throwable), KernelEvents::EXCEPTION);

        return $event->getResponse();
    }

    private function createEvent(Throwable $throwable): ExceptionEvent
    {
        return new ExceptionEvent(
            static::createStub(HttpKernelInterface::class),
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            $throwable,
        );
    }
}
