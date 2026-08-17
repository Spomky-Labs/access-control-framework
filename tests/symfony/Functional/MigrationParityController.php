<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\Controller\AccessControlTrait;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Twig\Environment;

/**
 * One controller for the three bricks a migration goes through, so that the same requester asks the
 * same question through each of them.
 *
 * Nothing here is written twice for the two stacks on purpose: this is the code an application
 * already has, and the point is that it does not move. The one line it does take is the trait,
 * AbstractController knowing only Security: it answers through whichever stack is registered, so
 * the three shapes below still run the very same method bodies.
 */
class MigrationParityController extends AbstractController
{
    use AccessControlTrait;

    /**
     * The helper FrameworkBundle offers to every controller. Through the trait it asks Security where
     * there is one and this component where there is not, so the three shapes must agree on what it
     * answers.
     */
    public function helperIsGranted(): Response
    {
        return new Response($this->isGranted('ROLE_ADMIN') ? 'granted' : 'denied');
    }

    /**
     * And the one that refuses on the spot. The exception is Security's in the first two shapes and
     * this component's in the third, which the status code has to hide.
     */
    public function helperDenyUnlessGranted(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN', null, 'Administrators only.');

        return new Response('reached');
    }

    /**
     * Carries nothing at all: the URL rule alone guards it, whichever key declares the rule.
     */
    public function guardedByARule(): Response
    {
        return new Response('reached');
    }

    #[IsGranted('ROLE_ADMIN')]
    public function guardedByTheAttribute(): Response
    {
        return new Response('reached');
    }

    public function template(Environment $twig): Response
    {
        return new Response($twig->render('is_granted.html.twig'));
    }

    /**
     * The functions this component does not answer. Kept apart so that the template above can be
     * compared across the three shapes while this one says what a template loses on the way out.
     */
    public function templateOfSecurityOnlyFunctions(Environment $twig): Response
    {
        return new Response($twig->render('security_only.html.twig'));
    }

    /**
     * This component's own way of asking why, which answers in every shape, unlike the one above.
     */
    public function templateOfTheComponentsDecision(Environment $twig): Response
    {
        return new Response($twig->render('access_control_decision.html.twig'));
    }
}
