<?php

declare(strict_types=1);

namespace AccessControl;

use function is_array;

readonly class AccessDecision
{
    /**
     * @var list<CastVote>
     */
    public array $votes;

    /**
     * The summary handed over by the strategy, followed by the reasons of the votes that concur with the decision.
     */
    public ?string $reason;

    /**
     * @param iterable<CastVote> $votes
     */
    public function __construct(
        public AccessRequest $accessRequest,
        public DecisionVote $decision,
        iterable $votes,
        ?string $summary = null,
    ) {
        $this->votes = is_array($votes) ? array_values($votes) : iterator_to_array($votes, false);

        $reasons = [];
        foreach ($this->votes as $vote) {
            if ($vote->outcome->decision === $decision && $vote->outcome->reason !== null) {
                $reasons[$vote->outcome->reason] = true;
            }
        }

        $this->reason = implode(' ', array_filter([$summary, ...array_keys($reasons)])) ?: null;
    }

    /**
     * The verdict alone, for the callers that only need to branch on it.
     *
     * The three way decision stays the truth of this object, an abstention being a result of its
     * own and not a refusal. This says whether access was granted, so an abstention answers false
     * exactly as a refusal does, which is what every entry point already does with it.
     */
    public function isGranted(): bool
    {
        return $this->decision === DecisionVote::ACCESS_GRANTED;
    }

    /**
     * @param iterable<CastVote> $votes
     */
    public static function grant(AccessRequest $accessRequest, iterable $votes, ?string $summary = null): self
    {
        return new self($accessRequest, DecisionVote::ACCESS_GRANTED, $votes, $summary);
    }

    /**
     * @param iterable<CastVote> $votes
     */
    public static function deny(AccessRequest $accessRequest, iterable $votes, ?string $summary = null): self
    {
        return new self($accessRequest, DecisionVote::ACCESS_DENIED, $votes, $summary);
    }

    /**
     * @param iterable<CastVote> $votes
     */
    public static function abstain(AccessRequest $accessRequest, iterable $votes, ?string $summary = null): self
    {
        return new self($accessRequest, DecisionVote::ACCESS_ABSTAIN, $votes, $summary);
    }
}
