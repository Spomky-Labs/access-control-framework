<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\All;
use AccessControl\Attribute\Argument;
use AccessControl\Attribute\When;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * Every method carries the Security attribute and its AccessControl counterpart side by side,
 * so that the parity test runs the very same controller through both listeners.
 */
class DuallyControlledController
{
    #[IsGranted('ROLE_ADMIN')]
    #[AccessPolicy('ROLE_ADMIN')]
    public function heldRole(): void
    {
    }

    #[IsGranted('ROLE_SUPER_ADMIN')]
    #[AccessPolicy('ROLE_SUPER_ADMIN')]
    public function unreachableRole(): void
    {
    }

    #[IsGranted('ROLE_USER')]
    #[AccessPolicy('ROLE_USER')]
    public function inheritedRole(): void
    {
    }

    #[IsGranted('read', 'post')]
    #[AccessPolicy('read', new Argument('post'))]
    public function subjectTakenFromAnArgument(Post $post): void
    {
    }

    #[IsGranted(new Expression("'ROLE_ADMIN' in role_names"))]
    #[AccessPolicy(new Expression("'ROLE_ADMIN' in role_names"))]
    public function grantingExpression(): void
    {
    }

    #[IsGranted(new Expression("'ROLE_SUPER_ADMIN' in role_names"))]
    #[AccessPolicy(new Expression("'ROLE_SUPER_ADMIN' in role_names"))]
    public function denyingExpression(): void
    {
    }

    #[IsGranted('ROLE_SUPER_ADMIN', message: 'Nope.')]
    #[AccessPolicy('ROLE_SUPER_ADMIN', message: 'Nope.')]
    public function customMessage(): void
    {
    }

    #[IsGranted('ROLE_ADMIN')]
    #[IsGranted('ROLE_USER')]
    #[All([new AccessPolicy('ROLE_ADMIN'), new AccessPolicy('ROLE_USER')])]
    public function repeatedAndAllGranted(): void
    {
    }

    #[IsGranted('ROLE_ADMIN')]
    #[IsGranted('ROLE_SUPER_ADMIN')]
    #[All([new AccessPolicy('ROLE_ADMIN'), new AccessPolicy('ROLE_SUPER_ADMIN')])]
    public function repeatedAndPartiallyGranted(): void
    {
    }

    #[IsGranted('ROLE_SUPER_ADMIN', methods: 'POST')]
    #[When(new Expression('request.isMethod("POST")'), [new AccessPolicy('ROLE_SUPER_ADMIN')])]
    public function filteredOnTheHttpMethod(): void
    {
    }

    #[IsGranted(new Expression('subject["post"].title == "Hello"'), ['post' => 'post'])]
    #[AccessPolicy(new Expression('subject["post"].title == "Hello"'), ['post' => new Argument('post')])]
    public function mapOfNamedSubjects(Post $post): void
    {
    }

    #[IsGranted('read', new Expression('args["post"]'))]
    #[AccessPolicy('read', new Argument('post'))]
    public function subjectFromAnExpression(Post $post): void
    {
    }

    #[IsGranted(new Expression('subject["post"].title == "Hello"'), ['post' => new Expression('args["post"]')])]
    #[AccessPolicy(new Expression('subject["post"].title == "Hello"'), ['post' => new Argument('post')])]
    public function mapOfSubjectsFromExpressions(Post $post): void
    {
    }
}
