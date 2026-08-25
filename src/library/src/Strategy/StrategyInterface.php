<?php

declare(strict_types=1);

namespace AccessControl\Strategy;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\CastVote;

/**
 * @experimental
 */
interface StrategyInterface
{
    public function getName(): string;

    /**
     * @param iterable<CastVote> $votes
     */
    public function evaluate(AccessRequest $accessRequest, iterable $votes): AccessDecision;
}
