<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

/**
 * A resource carrying what the discretionary and the mandatory models each need to decide.
 */
final readonly class Document
{
    /**
     * @param array<string, list<string>> $grants Permissions the owner handed over, indexed by attribute
     */
    public function __construct(
        public string $name,
        public string $owner = '',
        public array $grants = [],
        public SecurityLabel $classification = new SecurityLabel(0),
    ) {
    }
}
