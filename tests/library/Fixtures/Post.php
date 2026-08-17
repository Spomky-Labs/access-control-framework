<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

final readonly class Post
{
    public function __construct(
        public string $title = 'Hello',
        public bool $published = true,
    ) {
    }
}
