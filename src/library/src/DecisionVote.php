<?php

declare(strict_types=1);

namespace AccessControl;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
enum DecisionVote: string
{
    case ACCESS_GRANTED = 'ACCESS_GRANTED';
    case ACCESS_DENIED = 'ACCESS_DENIED';
    case ACCESS_ABSTAIN = 'ACCESS_ABSTAIN';
}
