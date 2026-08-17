<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\All;
use AccessControl\Attribute\Argument;
use AccessControl\Attribute\AtLeastOneOf;

class AccessControlledController
{
    public function noAttribute(): void
    {
    }

    #[AccessPolicy('ROLE_ADMIN')]
    public function granted(): void
    {
    }

    #[AccessPolicy('ROLE_SUPER_ADMIN')]
    public function denied(): void
    {
    }

    #[AccessPolicy('ROLE_SUPER_ADMIN', message: 'Nope.')]
    public function deniedWithACustomMessage(): void
    {
    }

    #[All([
        new AccessPolicy('read', new Argument('post')),
        new AccessPolicy('not-before', '2026-01-01'),
        new AccessPolicy('internal-ip-address'),
    ])]
    public function realWorldExample(Post $post): void
    {
    }

    #[All([new AccessPolicy('ROLE_ADMIN'), new AccessPolicy('ROLE_USER')])]
    public function allGranted(): void
    {
    }

    #[All([new AccessPolicy('ROLE_ADMIN'), new AccessPolicy('ROLE_SUPER_ADMIN')])]
    public function allPartiallyGranted(): void
    {
    }

    #[AtLeastOneOf([new AccessPolicy('ROLE_SUPER_ADMIN'), new AccessPolicy('ROLE_ADMIN')])]
    public function atLeastOneOfGranted(): void
    {
    }

    #[AtLeastOneOf([new AccessPolicy('ROLE_SUPER_ADMIN'), new AccessPolicy('ROLE_MODERATOR')])]
    public function atLeastOneOfDenied(): void
    {
    }

    #[All([
        new AccessPolicy('ROLE_ADMIN'),
        new AtLeastOneOf([
            new AccessPolicy('ROLE_MODERATOR'),
            new All([
                new AccessPolicy('ROLE_USER'),
                new AccessPolicy('ROLE_ADMIN'),
            ]),
        ]),
    ])]
    public function nested(): void
    {
    }

    #[All([
        new AccessPolicy('ROLE_ADMIN'),
        new AtLeastOneOf([
            new AccessPolicy('ROLE_MODERATOR'),
            new AccessPolicy('ROLE_SUPER_ADMIN'),
        ]),
    ], message: 'Nope.')]
    public function nestedDenied(): void
    {
    }

    #[All([
        new AccessPolicy('ROLE_ADMIN'),
        new Not([new AccessPolicy('ROLE_SUPER_ADMIN')]),
    ])]
    public function userlandCombinator(): void
    {
    }

    #[Not([new AccessPolicy('ROLE_ADMIN')])]
    public function userlandCombinatorDenied(): void
    {
    }

    #[Inapplicable]
    public function inapplicable(): void
    {
    }

    #[All([new Inapplicable(), new AccessPolicy('ROLE_ADMIN')])]
    public function inapplicableAmongApplicable(): void
    {
    }

    #[All([new Inapplicable(), new AccessPolicy('ROLE_SUPER_ADMIN')])]
    public function inapplicableAmongDenied(): void
    {
    }
}
