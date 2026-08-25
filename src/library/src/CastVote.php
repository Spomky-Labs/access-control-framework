<?php

declare(strict_types=1);

namespace AccessControl;

/**
 * A vote and the voter who cast it.
 *
 * An AccessOutcome says what a voter answered and why, and deliberately not who answered: a voter
 * builds one on its own and has no business naming itself, and a handler builds one without any
 * voter at all. The pairing therefore belongs to the manager, which is the only place that knows
 * both, and it lives in the decision rather than on the outcome.
 *
 * This is what lets a decision be read after the fact and still say who refused, which the reason
 * alone cannot: two voters may refuse for the same reason, and a template or a test wanting to name
 * the culprit had no way to.
 *
 * @experimental
 */
final readonly class CastVote
{
    public function __construct(
        public VoterInterface $voter,
        public AccessOutcome $outcome,
    ) {
    }
}
