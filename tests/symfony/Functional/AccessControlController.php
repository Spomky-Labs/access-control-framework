<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\All;
use AccessControl\Attribute\When;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class AccessControlController
{
    #[Route('/open', name: 'access_control_open')]
    public function open(): Response
    {
        return new Response('open');
    }

    #[Route('/edit', name: 'access_control_edit')]
    #[AccessPolicy('EDIT')]
    public function edit(): Response
    {
        return new Response('edited');
    }

    #[Route('/delete', name: 'access_control_delete')]
    #[AccessPolicy('DELETE')]
    public function delete(): Response
    {
        return new Response('deleted');
    }

    #[Route('/both', name: 'access_control_both')]
    #[All([new AccessPolicy('EDIT'), new AccessPolicy('DELETE')])]
    public function both(): Response
    {
        return new Response('both');
    }

    #[Route('/conditional', name: 'access_control_conditional', methods: ['GET', 'POST'])]
    #[When(new Expression('request.isMethod("POST")'), [new AccessPolicy('DELETE')])]
    public function conditional(): Response
    {
        return new Response('conditional');
    }

    #[Route('/custom-message', name: 'access_control_custom_message')]
    #[AccessPolicy('DELETE', message: 'You may not delete this.')]
    public function customMessage(): Response
    {
        return new Response('never reached');
    }
}
