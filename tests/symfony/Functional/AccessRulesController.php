<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Not one method carries an access policy, which is the point: what guards these is the rule map
 * built from configuration, the way security.access_control has always worked.
 */
class AccessRulesController
{
    /**
     * @var list<string>
     */
    public static array $reached = [];

    #[Route('/open', name: 'access_rules_open')]
    public function open(): Response
    {
        return new Response('open');
    }

    #[Route('/admin', name: 'access_rules_admin')]
    public function admin(): Response
    {
        self::$reached[] = 'admin';

        return new Response('admin');
    }

    #[Route('/staff', name: 'access_rules_staff')]
    public function staff(): Response
    {
        return new Response('staff');
    }

    #[Route('/local', name: 'access_rules_local')]
    public function local(): Response
    {
        return new Response('local');
    }

    #[Route('/posted', name: 'access_rules_posted', methods: ['GET', 'POST'])]
    public function posted(): Response
    {
        return new Response('posted');
    }

    #[Route('/secure', name: 'access_rules_secure')]
    public function secure(): Response
    {
        return new Response('secure');
    }

    #[Route('/by-route', name: 'access_rules_by_route')]
    public function byRoute(): Response
    {
        return new Response('by route');
    }
}
