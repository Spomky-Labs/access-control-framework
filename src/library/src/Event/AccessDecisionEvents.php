<?php

declare(strict_types=1);

namespace AccessControl\Event;

use AccessControl\DecisionVote;
use AccessControl\VoterInterface;

/**
 * Everything that was decided during a request, a command or a message, in the order it happened.
 *
 * The arrival order is kept rather than three separate lists, because it is what says which
 * decisions answered the same question: a query closes everything recorded since the previous one.
 *
 * The votes are kept alongside the decisions even though a decision now names its voters, because
 * a vote is recorded as it is cast: a strategy that drops one still leaves its trace here.
 *
 * The policies are kept for a different reason again: a composite is what makes a verdict, and the
 * decisions under it never say which operator combined them.
 */
final class AccessDecisionEvents
{
    /**
     * @var list<AccessDecisionEvent|VoteEvent|AccessQueryEvent|AccessPolicyEvent>
     */
    private array $events = [];

    /**
     * @var array<int, array{name: string, file: string|null, line: int|null}>
     */
    private array $callers = [];

    /**
     * @param array{name: string, file: string|null, line: int|null}|null $caller Where the decision was asked for, when the stack was walked
     */
    public function add(AccessDecisionEvent|VoteEvent|AccessQueryEvent|AccessPolicyEvent $event, ?array $caller = null): void
    {
        $this->events[] = $event;

        if ($caller !== null) {
            $this->callers[spl_object_id($event)] = $caller;
        }
    }

    /**
     * @return array{name: string, file: string|null, line: int|null}|null
     */
    public function getCaller(AccessDecisionEvent $event): ?array
    {
        return $this->callers[spl_object_id($event)] ?? null;
    }

    /**
     * @return list<AccessDecisionEvent|VoteEvent|AccessQueryEvent|AccessPolicyEvent>
     */
    public function all(): array
    {
        return $this->events;
    }

    /**
     * @return list<AccessDecisionEvent>
     */
    public function getDecisions(): array
    {
        return $this->only(AccessDecisionEvent::class);
    }

    /**
     * @return list<VoteEvent>
     */
    public function getVotes(): array
    {
        return $this->only(VoteEvent::class);
    }

    /**
     * @return list<AccessQueryEvent>
     */
    public function getQueries(): array
    {
        return $this->only(AccessQueryEvent::class);
    }

    /**
     * @return list<AccessPolicyEvent>
     */
    public function getPolicies(): array
    {
        return $this->only(AccessPolicyEvent::class);
    }

    /**
     * The decisions reached on a given attribute, in the order they were reached.
     *
     * Nested questions are in there too, an expression calling is_granted() producing a decision of
     * its own, so a request may hold more decisions than it has policies.
     *
     * @return list<AccessDecisionEvent>
     */
    public function getDecisionsOn(mixed $attribute): array
    {
        return array_values(array_filter(
            $this->getDecisions(),
            static fn (AccessDecisionEvent $event): bool => $event->accessRequest->attribute === $attribute,
        ));
    }

    /**
     * @param class-string<VoterInterface> $voter
     *
     * @return list<VoteEvent>
     */
    public function getVotesBy(string $voter, ?DecisionVote $decision = null): array
    {
        return array_values(array_filter(
            $this->getVotes(),
            static fn (VoteEvent $event): bool => $event->voter instanceof $voter
                && ($decision === null || $decision === $event->voterOutcome->decision),
        ));
    }

    /**
     * @template T of AccessDecisionEvent|VoteEvent|AccessQueryEvent|AccessPolicyEvent
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    private function only(string $class): array
    {
        return array_values(array_filter($this->events, static fn (object $event): bool => $event instanceof $class));
    }
}
