<?php

declare(strict_types=1);

namespace AccessControl\Event;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final class VoteEvent extends Event
{
    public function __construct(
        public readonly VoterInterface $voter,
        public readonly AccessRequest $accessRequest,
        public readonly AccessOutcome $voterOutcome,
    ) {
    }
}
