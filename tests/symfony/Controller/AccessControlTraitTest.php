<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Controller;

use AccessControl\AccessControlManager;
use AccessControl\AccessOutcome;
use AccessControl\Bundle\Controller\AccessControlTrait;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\RequesterBoundChecker;
use AccessControl\Tests\Fixtures\FixedOutcomeVoter;
use LogicException;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException as SecurityAccessDeniedException;

/**
 * The trait against a base controller that only knows Security, which is what an application has
 * wherever the component and the bundle are not part of Symfony.
 */
final class AccessControlTraitTest extends TestCase
{
    public function testTheBaseControllerAloneCannotAnswer()
    {
        $controller = new class() extends AbstractControllerWithoutAccessControl {
            public function ask(): bool
            {
                return $this->isGranted('ROLE_ADMIN');
            }
        };
        $controller->setContainer(new Container());

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('The SecurityBundle is not registered');

        $controller->ask();
    }

    public function testTheTraitAnswersWhereTheBaseControllerRaised()
    {
        $controller = $this->controller();
        $controller->setContainer($this->container(accessControl: true));

        static::assertTrue($controller->ask('ROLE_ADMIN'));
        static::assertFalse($controller->ask('ROLE_ACCOUNTANT'));
    }

    /**
     * The one failure the trait must not have. Answering through the component while a firewall is
     * in place would walk past its checker without a word.
     */
    public function testSecurityKeepsAnsweringWhenItIsThere()
    {
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authorizationChecker->expects(static::once())
            ->method('isGranted')
            ->willReturn(true);

        $container = $this->container(accessControl: false);
        $container->set('security.authorization_checker', $authorizationChecker);

        $controller = $this->controller();
        $controller->setContainer($container);

        static::assertTrue($controller->ask('ROLE_ADMIN'));
    }

    public function testADenialRaisesTheComponentException()
    {
        $controller = $this->controller();
        $controller->setContainer($this->container(accessControl: true));

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessageIsOrContains('Administrators only.');

        $controller->deny('ROLE_ACCOUNTANT', 'Administrators only.');
    }

    public function testAGrantedRequestGoesThrough()
    {
        $controller = $this->controller();
        $controller->setContainer($this->container(accessControl: true));
        $controller->deny('ROLE_ADMIN', 'Administrators only.');

        $this->expectNotToPerformAssertions();
    }

    /**
     * With Security the parent keeps answering, so its exception carries the attributes and the
     * subject, which its exception listener and its error pages read.
     */
    public function testADenialIsLeftToTheParentWhenSecurityIsThere()
    {
        $authorizationChecker = static::createStub(AuthorizationCheckerInterface::class);
        $authorizationChecker->method('isGranted')
            ->willReturn(false);

        $container = $this->container(accessControl: true);
        $container->set('security.authorization_checker', $authorizationChecker);

        $controller = $this->controller();
        $controller->setContainer($container);

        try {
            $controller->deny('ROLE_ADMIN', 'Administrators only.');
            static::fail('Access should have been denied.');
        } catch (SecurityAccessDeniedException $exception) {
            static::assertSame('Administrators only.', $exception->getMessage());
            static::assertSame(['ROLE_ADMIN'], $exception->getAttributes());
        }
    }

    /**
     * The parent reads func_num_args() to tell a message given from a message left out, so the
     * trait has to forward the call rather than pass its three parameters along.
     */
    public function testTheNumberOfArgumentsSurvivesTheForwarding()
    {
        $authorizationChecker = static::createStub(AuthorizationCheckerInterface::class);
        $authorizationChecker->method('isGranted')
            ->willReturn(false);

        $container = $this->container(accessControl: true);
        $container->set('security.authorization_checker', $authorizationChecker);

        $controller = $this->controller();
        $controller->setContainer($container);

        $this->expectException(SecurityAccessDeniedException::class);
        $this->expectExceptionMessageIsOrContains('Denied by Security.');

        $controller->denyWithoutAMessage('ROLE_ADMIN');
    }

    /**
     * The services of the base controller have to survive, the trait adding to them rather than
     * taking their place.
     */
    public function testTheSubscribedServicesAreAddedToTheInheritedOnes()
    {
        $services = $this->controller()::getSubscribedServices();

        static::assertSame('?' . RequesterBoundChecker::class, $services['access_control.checker']);
        static::assertSame('?' . AuthorizationCheckerInterface::class, $services['security.authorization_checker']);
    }

    /**
     * On the AbstractController of this repository the trait is redundant, that one answering
     * through AccessControl on its own. It still has to fit: a clash of visibility or of signature
     * would raise when the class is declared, not when it is used.
     */
    public function testItFitsOnTheAbstractControllerOfThisRepository()
    {
        $controller = new class() extends AbstractController {
            use AccessControlTrait;

            public function ask(mixed $attribute): bool
            {
                return $this->isGranted($attribute);
            }
        };
        $controller->setContainer($this->container(accessControl: true));

        static::assertTrue($controller->ask('ROLE_ADMIN'));
        static::assertArrayHasKey('router', $controller::getSubscribedServices());
    }

    private function controller(): object
    {
        return new class() extends AbstractControllerWithoutAccessControl {
            use AccessControlTrait;

            public function ask(mixed $attribute): bool
            {
                return $this->isGranted($attribute);
            }

            public function deny(mixed $attribute, string $message): void
            {
                $this->denyAccessUnlessGranted($attribute, null, $message);
            }

            public function denyWithoutAMessage(mixed $attribute): void
            {
                $this->denyAccessUnlessGranted($attribute);
            }
        };
    }

    private function container(bool $accessControl): Container
    {
        $container = new Container();

        if ($accessControl) {
            $container->set('access_control.checker', new RequesterBoundChecker(
                new AccessControlManager([], [new FixedOutcomeVoter(AccessOutcome::grant('Granted.'), ['ROLE_ADMIN'])]),
                new StaticRequesterProvider(),
            ));
        }

        return $container;
    }
}
