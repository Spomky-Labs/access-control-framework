<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\Controller\AccessControlTrait;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * The helpers of AbstractController, in an application that has no Security. Both raise a
 * LogicException telling the developer to install SecurityBundle, which is what the trait is for.
 */
class HelperController extends AbstractController
{
    use AccessControlTrait;

    #[Route('/is-granted', name: 'access_control_helper_is_granted')]
    public function granted(): Response
    {
        return new Response($this->isGranted('ROLE_ADMIN') ? 'granted' : 'denied');
    }

    #[Route('/deny-unless', name: 'access_control_helper_deny_unless')]
    public function denyUnless(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN', null, 'Administrators only.');

        return new Response('reached');
    }

    /**
     * Security's attribute, in an application that no longer has Security. It used to be read by
     * nobody, so this controller answered 200 whatever the requester held.
     */
    #[Route('/is-granted-attribute', name: 'access_control_helper_attribute')]
    #[IsGranted('ROLE_ADMIN', message: 'Administrators only.')]
    public function isGrantedAttribute(): Response
    {
        return new Response('reached');
    }

    #[Route('/is-granted-status', name: 'access_control_helper_attribute_status')]
    #[IsGranted('ROLE_ADMIN', statusCode: 404)]
    public function isGrantedWithAStatusCode(): Response
    {
        return new Response('reached');
    }
}
