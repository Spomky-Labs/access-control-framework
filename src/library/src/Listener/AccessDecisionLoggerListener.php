<?php

declare(strict_types=1);

namespace AccessControl\Listener;

use AccessControl\Event\AccessDecisionEvent;
use AccessControl\Event\AccessDecisionEvents;
use AccessControl\Event\AccessPolicyEvent;
use AccessControl\Event\AccessQueryEvent;
use AccessControl\Event\VoteEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Contracts\Service\ResetInterface;
use const DEBUG_BACKTRACE_IGNORE_ARGS;

/**
 * Keeps every decision and every vote, so that an integration test can tell why access was refused.
 *
 * The response carries no diagnostic on purpose, and this is what fills that gap where it is safe
 * to: in the test, not in the answer sent to the requester.
 *
 * @experimental
 */
final class AccessDecisionLoggerListener implements EventSubscriberInterface, ResetInterface
{
    private AccessDecisionEvents $events;

    /**
     * @param bool $traceCallers Whether to walk the stack for the call site of every decision, which
     *                           only pays for itself in debug: it is what names a decision nobody
     *                           declared an origin for, a template or a service asking on its own
     */
    public function __construct(
        private readonly bool $traceCallers = false,
    ) {
        $this->events = new AccessDecisionEvents();
    }

    public function reset(): void
    {
        $this->events = new AccessDecisionEvents();
    }

    public function onAccessDecision(AccessDecisionEvent $event): void
    {
        $this->events->add($event, $this->traceCallers ? self::caller() : null);
    }

    public function onVote(VoteEvent $event): void
    {
        $this->events->add($event);
    }

    public function onQuery(AccessQueryEvent $event): void
    {
        $this->events->add($event);
    }

    public function onPolicy(AccessPolicyEvent $event): void
    {
        $this->events->add($event);
    }

    public function getEvents(): AccessDecisionEvents
    {
        return $this->events;
    }

    /**
     * The first frame that belongs neither to the component nor to the dispatcher is the one that
     * asked; the file and line come from the frame before it, which is the call itself.
     *
     * The fixtures of the component are not the component, and a test asking on its own deserves to
     * be named like any other caller, which is why the Tests namespace is excluded from the skip.
     *
     * @return array{name: string, file: string|null, line: int|null}|null
     */
    private static function caller(): ?array
    {
        $previous = null;

        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 16) as $frame) {
            $class = $frame['class'] ?? null;

            if ($class !== null
                && (str_starts_with($class, __NAMESPACE__) || str_starts_with($class, 'AccessControl\\') || str_contains($class, 'EventDispatcher'))
                && ! str_starts_with($class, 'AccessControl\\Tests\\')
            ) {
                $previous = $frame;

                continue;
            }

            return [
                'name' => $class === null ? $frame['function'] : $class . '::' . $frame['function'],
                'file' => $previous['file'] ?? null,
                'line' => $previous['line'] ?? null,
            ];
        }

        return null;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            AccessDecisionEvent::class => ['onAccessDecision', -255],
            VoteEvent::class => ['onVote', -255],
            AccessQueryEvent::class => ['onQuery', -255],
            AccessPolicyEvent::class => ['onPolicy', -255],
        ];
    }
}
