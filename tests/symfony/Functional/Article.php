<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Component\Validator\Constraints\NotBlank;

class Article
{
    public ?string $marking = null;

    /**
     * Left blank by default, so that is_valid(subject) has something to refuse.
     */
    #[NotBlank]
    public ?string $title = null;
}
