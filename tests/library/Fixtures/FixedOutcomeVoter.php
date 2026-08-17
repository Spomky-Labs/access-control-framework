<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

final readonly class FixedOutcomeVoter implements VoterInterface
{
    /**
     * @param list<string> $supportedAttributes An empty list supports every attribute
     */
    public function __construct(
        private AccessOutcome $outcome,
        private array $supportedAttributes = [],
    ) {
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        return $this->outcome;
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return [] === $this->supportedAttributes || \in_array($attribute, $this->supportedAttributes, true);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }
}
