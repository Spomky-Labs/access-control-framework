<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

/**
 * A point of the security lattice: a hierarchical level plus a set of compartments.
 *
 * Two labels may be incomparable, neither dominating the other.
 */
final readonly class SecurityLabel
{
    /**
     * @param list<string> $compartments
     */
    public function __construct(
        public int $level,
        public array $compartments = [],
    ) {
    }

    public function dominates(self $other): bool
    {
        return $this->level >= $other->level && [] === array_diff($other->compartments, $this->compartments);
    }

    public function __toString(): string
    {
        return $this->compartments ? \sprintf('%d{%s}', $this->level, implode(',', $this->compartments)) : (string) $this->level;
    }
}
