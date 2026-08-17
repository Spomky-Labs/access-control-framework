<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Attribute\AccessPolicy;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * The same question asked twice on two routes, once with the Security attribute and once with its
 * AccessControl counterpart. Both are behind the same firewall, so the only difference is which
 * stack answers.
 */
class SecurityParityController
{
    /**
     * No attribute at all on the three below: what guards them is security.access_control, the
     * firewall rules, which is the most used feature of the lot.
     */
    #[Route('/dashboard/admin', name: 'parity_dashboard_admin')]
    public function dashboardAdmin(): Response
    {
        return new Response('ok');
    }

    #[Route('/dashboard', name: 'parity_dashboard')]
    public function dashboard(): Response
    {
        return new Response('ok');
    }

    #[Route('/anonymous', name: 'parity_anonymous')]
    public function anonymous(): Response
    {
        return new Response('ok');
    }

    #[Route('/either', name: 'parity_either')]
    public function either(): Response
    {
        return new Response('ok');
    }

    #[Route('/allow-if', name: 'parity_allow_if')]
    public function allowIf(): Response
    {
        return new Response('ok');
    }

    #[Route('/by-ip', name: 'parity_by_ip')]
    public function byIp(): Response
    {
        return new Response('ok');
    }

    #[Route('/by-method', name: 'parity_by_method', methods: ['GET', 'POST'])]
    public function byMethod(): Response
    {
        return new Response('ok');
    }

    #[Route('/by-host', name: 'parity_by_host')]
    public function byHost(): Response
    {
        return new Response('ok');
    }

    #[Route('/secure-channel', name: 'parity_secure_channel')]
    public function secureChannel(): Response
    {
        return new Response('ok');
    }

    #[Route('/security/held-role', name: 'parity_security_held_role')]
    #[IsGranted('ROLE_USER')]
    public function securityHeldRole(): Response
    {
        return new Response('ok');
    }

    #[Route('/access-control/held-role', name: 'parity_access_control_held_role')]
    #[AccessPolicy('ROLE_USER')]
    public function accessControlHeldRole(): Response
    {
        return new Response('ok');
    }

    #[Route('/security/unreachable-role', name: 'parity_security_unreachable_role')]
    #[IsGranted('ROLE_SUPER_ADMIN')]
    public function securityUnreachableRole(): Response
    {
        return new Response('ok');
    }

    #[Route('/access-control/unreachable-role', name: 'parity_access_control_unreachable_role')]
    #[AccessPolicy('ROLE_SUPER_ADMIN')]
    public function accessControlUnreachableRole(): Response
    {
        return new Response('ok');
    }

    #[Route('/security/authenticated', name: 'parity_security_authenticated')]
    #[IsGranted('IS_AUTHENTICATED_FULLY')]
    public function securityAuthenticated(): Response
    {
        return new Response('ok');
    }

    #[Route('/access-control/authenticated', name: 'parity_access_control_authenticated')]
    #[AccessPolicy('IS_AUTHENTICATED_FULLY')]
    public function accessControlAuthenticated(): Response
    {
        return new Response('ok');
    }

    #[Route('/security/application-voter', name: 'parity_security_application_voter')]
    #[IsGranted('APP_PERMISSION')]
    public function securityApplicationVoter(): Response
    {
        return new Response('ok');
    }

    #[Route('/access-control/application-voter', name: 'parity_access_control_application_voter')]
    #[AccessPolicy('APP_PERMISSION')]
    public function accessControlApplicationVoter(): Response
    {
        return new Response('ok');
    }

    #[Route('/security/public', name: 'parity_security_public')]
    #[IsGranted('PUBLIC_ACCESS')]
    public function securityPublic(): Response
    {
        return new Response('ok');
    }

    #[Route('/access-control/public', name: 'parity_access_control_public')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function accessControlPublic(): Response
    {
        return new Response('ok');
    }
}
