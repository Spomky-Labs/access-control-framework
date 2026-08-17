<?php

declare(strict_types=1);

namespace AccessControl\Event;

use AccessControl\DecisionVote;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * One thing a caller wanted to know, whatever number of decisions it took to answer.
 *
 * A composite policy asks a question per branch, and a firewall rule naming several roles asks one
 * per role, so a flat log of decisions cannot say which of them were the same question. This closes
 * a question, and everything recorded since the previous one belongs to it.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final class AccessQueryEvent extends Event
{
    /**
     * @param string|null $origin What asked, as an entry point can name itself where the decisions
     *                            it takes cannot
     */
    public function __construct(
        public readonly DecisionVote $decision,
        public readonly ?string $origin = null,
    ) {
    }
}
