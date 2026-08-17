<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

final class SubjectRecordingVoter implements VoterInterface
{
    /**
     * @var list<mixed>
     */
    public array $subjects = [];

    /**
     * @var list<array<string, mixed>>
     */
    public array $environment = [];

    public function __construct(
        private readonly string $supportedAttribute,
    ) {
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $this->subjects[] = $accessRequest->subject;
        $this->environment[] = iterator_to_array($accessRequest->environment);

        return AccessOutcome::grant('Granted.');
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return $this->supportedAttribute === $attribute;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }
}
