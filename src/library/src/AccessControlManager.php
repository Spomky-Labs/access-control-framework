<?php

declare(strict_types=1);

namespace AccessControl;

use AccessControl\Event\AccessDecisionEvent;
use AccessControl\Event\VoteEvent;
use AccessControl\Exception\InvalidStrategyException;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Strategy\StrategyInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use function is_array;
use function is_string;
use function sprintf;

/**
 * @experimental
 */
final class AccessControlManager implements AccessControlManagerInterface
{
    private readonly string $defaultStrategy;

    /**
     * @var array<string, StrategyInterface>
     */
    private readonly array $strategies;

    /**
     * @var array<string, array<array-key, bool>>
     */
    private array $votersCacheAttributes = [];

    /**
     * @var list<VoterInterface>|null
     */
    private ?array $votersList = null;

    /**
     * The requests being decided, innermost last.
     *
     * @var list<AccessRequest>
     */
    private array $pending = [];

    /**
     * @param iterable<StrategyInterface> $strategies
     * @param iterable<VoterInterface>    $voters
     */
    public function __construct(
        iterable $strategies,
        private readonly iterable $voters,
        ?string $defaultStrategy = null,
        private readonly ?EventDispatcherInterface $dispatcher = null,
        /**
         * What to answer when no voter had anything to say, for every request that does not settle
         * it itself. Security carries the same choice on each of its strategies; here it belongs to
         * the manager, so that one setting is obeyed by every entry point rather than by the ones
         * that remembered to pass it.
         */
        private readonly bool $allowIfAllAbstain = false,
    ) {
        $namedStrategies = [];
        foreach ($strategies as $strategy) {
            $name = $strategy->getName();
            if (isset($namedStrategies[$name])) {
                throw new InvalidStrategyException(sprintf('Strategy "%s" is registered twice, by "%s" and "%s".', $name, get_debug_type($namedStrategies[$name]), get_debug_type($strategy)));
            }
            $namedStrategies[$name] = $strategy;
        }

        if (! $namedStrategies) {
            $permitOverridesStrategy = new PermitOverridesStrategy();
            $namedStrategies[$permitOverridesStrategy->getName()] = $permitOverridesStrategy;
        }

        $defaultStrategy ??= array_key_first($namedStrategies);

        if (! isset($namedStrategies[$defaultStrategy])) {
            throw new InvalidStrategyException(sprintf('The default strategy "%s" is not registered. Registered strategies are: "%s".', $defaultStrategy, implode('", "', array_keys($namedStrategies))));
        }

        $this->defaultStrategy = $defaultStrategy;
        $this->strategies = $namedStrategies;
    }

    /**
     * Drops the memoized voter support, which grows with the number of distinct attributes met.
     *
     * Long running processes should call this between requests or messages. The materialized
     * voter list is deliberately kept, as the given iterable may not be replayable.
     */
    public function reset(): void
    {
        $this->votersCacheAttributes = [];
        $this->pending = [];
    }

    /**
     * A voter may ask a further question, an expression calling is_granted() being the usual case,
     * and the decision it leads to is then not a sibling of this one but a child of it. The pending
     * stack is what records that parentage, so the profiler can show a tree rather than a flat list.
     */
    public function decide(AccessRequest $accessRequest, ?string $strategy = null): AccessDecision
    {
        $strategy ??= $this->defaultStrategy;
        if (! isset($this->strategies[$strategy])) {
            throw new InvalidStrategyException(sprintf('Strategy "%s" is not registered. Registered strategies are: "%s".', $strategy, implode('", "', array_keys($this->strategies))));
        }

        $parent = $this->pending ? $this->pending[array_key_last($this->pending)] : null;
        $this->pending[] = $accessRequest;

        try {
            $votes = [];
            foreach ($this->getVoters($accessRequest) as $voter) {
                $vote = $voter->vote($accessRequest);
                $votes[] = new CastVote($voter, $vote);
                $this->dispatcher?->dispatch(new VoteEvent($voter, $accessRequest, $vote));
            }

            $accessDecision = $this->strategies[$strategy]->evaluate($accessRequest, $votes);

            if ($accessDecision->decision === DecisionVote::ACCESS_ABSTAIN) {
                $summary = $accessDecision->reason;
                $accessDecision = ($accessRequest->allowIfAllAbstain ?? $this->allowIfAllAbstain)
                    ? AccessDecision::grant($accessRequest, $votes, $summary)
                    : AccessDecision::deny($accessRequest, $votes, $summary);
            }
        } finally {
            array_pop($this->pending);
        }

        $this->dispatcher?->dispatch(new AccessDecisionEvent($accessRequest, $accessDecision, $strategy, $parent));

        return $accessDecision;
    }

    /**
     * @return iterable<VoterInterface>
     */
    private function getVoters(AccessRequest $accessRequest): iterable
    {
        $this->votersList ??= is_array($this->voters) ? array_values($this->voters) : iterator_to_array($this->voters, false);

        $keyAttribute = is_string($accessRequest->attribute) ? $accessRequest->attribute : null;

        foreach ($this->votersList as $key => $voter) {
            if ($keyAttribute === null) {
                if (! $voter->supportsAttribute($accessRequest->attribute)) {
                    continue;
                }
            } else {
                if (! isset($this->votersCacheAttributes[$keyAttribute][$key])) {
                    $this->votersCacheAttributes[$keyAttribute][$key] = $voter->supportsAttribute($accessRequest->attribute);
                }
                if (! $this->votersCacheAttributes[$keyAttribute][$key]) {
                    continue;
                }
            }

            if (! $voter->supportsSubject($accessRequest->subject)) {
                continue;
            }

            yield $voter;
        }
    }
}
