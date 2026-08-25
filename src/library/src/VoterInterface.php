<?php

declare(strict_types=1);

namespace AccessControl;

/**
 * @experimental
 */
interface VoterInterface
{
    public function vote(AccessRequest $accessRequest): AccessOutcome;

    public function supportsAttribute(mixed $attribute): bool;

    public function supportsSubject(mixed $subject): bool;
}
