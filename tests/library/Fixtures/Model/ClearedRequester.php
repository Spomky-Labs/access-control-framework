<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

final readonly class ClearedRequester
{
    public function __construct(
        public string $name,
        public SecurityLabel $clearance,
    ) {
    }
}
