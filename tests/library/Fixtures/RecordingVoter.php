<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use function in_array;

final class RecordingVoter implements VoterInterface
{
    /**
     * @var list<mixed>
     */
    public array $supportsAttributeCalls = [];

    /**
     * @var list<string>
     */
    public array $supportsSubjectCalls = [];

    /**
     * @var list<mixed>
     */
    public array $voteCalls = [];

    /**
     * @param list<string> $supportedAttributes
     * @param list<string> $supportedTypes
     */
    public function __construct(
        private readonly array $supportedAttributes,
        private readonly ?array $supportedTypes = null,
    ) {
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $this->voteCalls[] = $accessRequest->attribute;

        return AccessOutcome::grant('Granted by the recording voter.');
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        $this->supportsAttributeCalls[] = $attribute;

        return in_array($attribute, $this->supportedAttributes, true);
    }

    public function supportsSubject(mixed $subject): bool
    {
        $subjectType = get_debug_type($subject);
        $this->supportsSubjectCalls[] = $subjectType;

        return $this->supportedTypes === null || in_array($subjectType, $this->supportedTypes, true);
    }
}
