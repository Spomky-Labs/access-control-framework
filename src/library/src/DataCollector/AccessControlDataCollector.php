<?php

declare(strict_types=1);

namespace AccessControl\DataCollector;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Bridge\Security\VoterAdapter;
use AccessControl\DecisionVote;
use AccessControl\Event\AccessDecisionEvent;
use AccessControl\Event\AccessPolicyEvent;
use AccessControl\Event\AccessQueryEvent;
use AccessControl\Listener\AccessDecisionLoggerListener;
use AccessControl\VoterInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\HttpKernel\DataCollector\LateDataCollectorInterface;
use Symfony\Component\VarDumper\Caster\ClassStub;
use Symfony\Component\VarDumper\Cloner\Data;

/**
 * Reads back what the decision logger recorded, and records nothing of its own.
 *
 * A decision keeps its votes, but a vote outcome does not know who cast it. The author is therefore
 * recovered by matching the outcomes the logger saw being cast against the ones the decision kept,
 * a join that belongs here rather than in the decision, which no application should have to carry a
 * profiler field for.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 *
 * @final
 */
class AccessControlDataCollector extends DataCollector implements LateDataCollectorInterface
{
    /**
     * @param iterable<VoterInterface> $voters
     */
    public function __construct(
        private readonly AccessDecisionLoggerListener $logger,
        private readonly iterable $voters = [],
        private readonly ?string $defaultStrategy = null,
        /**
         * What the same algorithm is called where the application declared it. This component keeps
         * the XACML names, Security has its own, and during a migration the developer reads a name
         * here that is not the one they wrote.
         */
        private readonly ?string $defaultStrategyAlias = null,
        /**
         * Which stack ends up answering each kind of question, as the bundle settled it when the
         * container was built. Two applications carrying the same two bundles can differ here, and
         * they look alike from the outside until one of them answers through the wrong engine.
         *
         * @var array<string, mixed>
         */
        private readonly array $integration = [],
    ) {
    }

    /**
     * Nothing to do here: the decisions are recorded live by the logger, and cloned as late as
     * possible.
     */
    public function collect(Request $request, Response $response, ?\Throwable $exception = null): void
    {
    }

    /**
     * What is left pending at the end was decided without anyone closing a question, a checker
     * called from a template or from a service being the usual case. Each of those is a question of
     * its own, so they are split rather than piled into one, and the stack says who asked. Such a
     * question declares no policy either, so it carries no tree.
     */
    public function lateCollect(): void
    {
        $events = $this->logger->getEvents();

        $queries = [];
        $pending = [];
        $pendingPolicies = [];
        $granted = 0;
        $decisionCount = 0;

        foreach ($events->all() as $event) {
            if ($event instanceof AccessQueryEvent) {
                $queries[] = [
                    'origin' => $event->origin,
                    'caller' => null,
                    'decision' => $event->decision->value,
                    'policies' => $this->inPreOrder($pendingPolicies),
                    'decisions' => $this->inPreOrder($pending),
                ];
                $pending = [];
                $pendingPolicies = [];

                continue;
            }

            if ($event instanceof AccessPolicyEvent) {
                $pendingPolicies[] = [
                    'id' => spl_object_id($event->accessPolicy),
                    'parent' => null === $event->parent ? null : spl_object_id($event->parent),
                    'policy' => new ClassStub($event->accessPolicy::class),
                    'attribute' => $event->accessPolicy instanceof AccessPolicy ? $event->accessPolicy->attribute : null,
                    'decision' => $event->outcome->decision->value,
                    'reason' => $event->outcome->reason,
                ];

                continue;
            }

            if (!$event instanceof AccessDecisionEvent) {
                continue;
            }

            ++$decisionCount;
            $granted += DecisionVote::ACCESS_GRANTED === $event->accessDecision->decision ? 1 : 0;

            $pending[] = [
                'id' => spl_object_id($event->accessRequest),
                'parent' => null === $event->parent ? null : spl_object_id($event->parent),
                'caller' => $events->getCaller($event),
            ] + $this->collectDecision($event);
        }

        foreach ($this->splitByRoot($pending) as $group) {
            $root = $group[array_key_last($group)];

            $queries[] = [
                'origin' => $root['caller']['name'] ?? null,
                'caller' => $root['caller'],
                'decision' => $root['decision'],
                'policies' => [],
                'decisions' => $this->inPreOrder($group),
            ];
        }

        $voters = [];
        foreach ($this->voters as $voter) {
            $voters[] = self::describe($voter);
        }

        $this->data = $this->cloneVar([
            'default_strategy' => $this->defaultStrategy,
            'default_strategy_alias' => $this->defaultStrategyAlias,
            'integration' => $this->integration,
            'voters' => $voters,
            'queries' => $queries,
            'decisions' => $decisionCount,
            'granted' => $granted,
            'denied' => $decisionCount - $granted,
        ]);
    }

    /**
     * A root decision completes after everything it led to, so it closes its own group.
     *
     * @param list<array<string, mixed>> $decisions
     *
     * @return list<list<array<string, mixed>>>
     */
    private function splitByRoot(array $decisions): array
    {
        $groups = [];
        $current = [];

        foreach ($decisions as $decision) {
            $current[] = $decision;

            if (null === $decision['parent']) {
                $groups[] = $current;
                $current = [];
            }
        }

        if ($current) {
            $groups[] = $current;
        }

        return $groups;
    }

    /**
     * A decision completes after the ones it led to, so the arrival order puts a nested decision
     * above the one that asked it. Walking the parent links restores the reading order, each
     * decision followed by what it went on to ask.
     *
     * @param list<array<string, mixed>> $decisions
     *
     * @return list<array<string, mixed>>
     */
    private function inPreOrder(array $decisions): array
    {
        $known = array_column($decisions, 'id', 'id');

        $byParent = [];
        foreach ($decisions as $index => $decision) {
            $parent = $decision['parent'];
            $byParent[null !== $parent && isset($known[$parent]) ? $parent : 'root'][] = $index;
        }

        $ordered = [];
        $walk = static function (string|int $parent, int $depth) use (&$walk, &$ordered, $byParent, $decisions): void {
            foreach ($byParent[$parent] ?? [] as $index) {
                $decision = $decisions[$index];
                $id = $decision['id'];
                unset($decision['id'], $decision['parent'], $decision['caller']);

                $ordered[] = ['depth' => $depth] + $decision;
                $walk($id, $depth + 1);
            }
        };
        $walk('root', 0);

        return $ordered;
    }

    /**
     * The author of a vote is read off the decision itself. It used to be joined from the VoteEvent
     * stream by position, which only held as long as every strategy kept every vote it was given.
     *
     * @return array<string, mixed>
     */
    private function collectDecision(AccessDecisionEvent $event): array
    {
        $votes = [];
        foreach ($event->accessDecision->votes as $cast) {
            $votes[] = self::describe($cast->voter) + [
                'voter' => null,
                'decision' => $cast->outcome->decision->value,
                'reason' => $cast->outcome->reason,
                'weight' => $cast->outcome->weight,
            ];
        }

        return [
            'decision' => $event->accessDecision->decision->value,
            'strategy' => $event->strategy,
            'reason' => $event->accessDecision->reason,
            'attribute' => $event->accessRequest->attribute,
            'subject' => $event->accessRequest->subject,
            'requester' => $event->accessRequest->requester,
            'environment' => iterator_to_array($event->accessRequest->environment),
            'votes' => $votes,
        ];
    }

    /**
     * A voter written against Security is consulted through an adapter, which the panel has to see
     * through: wrapped, every one of them would read as the same class.
     *
     * The key is left out rather than set to null when there is nothing behind: seek() on a null
     * value hands back a Data wrapping it, on which Twig's empty test calls count() and fails.
     *
     * @return array{voter: ClassStub, bridged?: ClassStub}
     */
    private static function describe(VoterInterface $voter): array
    {
        $described = ['voter' => new ClassStub($voter::class)];

        if ($voter instanceof VoterAdapter) {
            $described['bridged'] = new ClassStub($voter->voter::class);
        }

        return $described;
    }

    public function getName(): string
    {
        return 'access_control';
    }

    public function getDefaultStrategy(): ?string
    {
        return $this->data['default_strategy'] ?? null;
    }

    /**
     * The name the same algorithm carries where the application declared it, when that is not the
     * one this component uses.
     */
    public function getDefaultStrategyAlias(): ?string
    {
        return $this->data['default_strategy_alias'] ?? null;
    }

    /**
     * Which stack answers each kind of question in this application.
     *
     * @return array<string, mixed>|Data
     */
    public function getIntegration(): array|Data
    {
        return $this->data['integration'] ?? [];
    }

    /**
     * The voters the application registered, whether they were consulted or not.
     *
     * @return array<array{voter: ClassStub, bridged?: ClassStub}>|Data
     */
    public function getVoters(): array|Data
    {
        return $this->data['voters'] ?? [];
    }

    /**
     * What was asked, in the order it was asked, each with the decisions it took to answer.
     *
     * A composite asks a question per branch and a firewall rule one per role, so a query usually
     * holds several decisions; a decision reached by a voter asking further carries a depth above
     * zero and belongs under the one before it.
     *
     * @return array<array<string, mixed>>|Data
     */
    public function getQueries(): array|Data
    {
        return $this->data['queries'] ?? [];
    }

    public function getDecisionCount(): int
    {
        return $this->data['decisions'] ?? 0;
    }

    public function getGrantedCount(): int
    {
        return $this->data['granted'] ?? 0;
    }

    public function getDeniedCount(): int
    {
        return $this->data['denied'] ?? 0;
    }
}
