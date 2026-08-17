<?php

declare(strict_types=1);

namespace AccessControl;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface VoterInterface
{
    public function vote(AccessRequest $accessRequest): AccessOutcome;

    public function supportsAttribute(mixed $attribute): bool;

    public function supportsSubject(mixed $subject): bool;
}
