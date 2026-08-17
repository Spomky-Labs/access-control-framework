<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\RequesterBoundChecker;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Environment;

/**
 * The two ways of asking in the middle of one's own work, without Security anywhere: the template
 * function, and the checker injected by type.
 */
class TwigController
{
    #[Route('/template', name: 'access_control_template')]
    public function template(Environment $twig): Response
    {
        return new Response($twig->render('is_granted.html.twig'));
    }

    #[Route('/injected', name: 'access_control_injected')]
    public function injected(RequesterBoundChecker $accessChecker): Response
    {
        return new Response($accessChecker->isGranted('ROLE_ADMIN') ? 'granted' : 'denied');
    }
}
