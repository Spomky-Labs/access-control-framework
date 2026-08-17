<?php

declare(strict_types=1);

namespace AccessControl;

use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Event\AccessPolicyEvent;
use AccessControl\Event\AccessQueryEvent;
use AccessControl\Exception\UnsupportedAccessPolicyException;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final class AccessPolicyEvaluator
{
    /**
     * @var list<AccessPolicyHandlerInterface>|null
     */
    private ?array $handlersList = null;

    /**
     * @var array<class-string<AccessPolicyInterface>, AccessPolicyHandlerInterface>
     */
    private array $handlersCache = [];

    /**
     * @var list<AccessPolicyInterface>
     */
    private array $pending = [];

    /**
     * @param iterable<AccessPolicyHandlerInterface> $handlers
     */
    public function __construct(
        private readonly iterable $handlers,
        private readonly ?EventDispatcherInterface $dispatcher = null,
    ) {
    }

    /**
     * A composite recurses through here, so only the outermost call closes a query: everything a
     * policy tree decided along the way belongs to the one question that was asked.
     *
     * Every node of the tree is recorded on the way out, with the composite it is a branch of. A
     * flat log of decisions cannot say which operator combined them, nor that a composite stepped
     * aside without asking anything, and this is the only place that sees the whole shape.
     */
    public function evaluate(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context): AccessOutcome
    {
        $handler = $this->handlersCache[$accessPolicy::class] ??= $this->findHandler($accessPolicy);

        $parent = $this->pending ? $this->pending[array_key_last($this->pending)] : null;
        $this->pending[] = $accessPolicy;

        try {
            $outcome = $handler->handle($accessPolicy, $context, $this);
        } finally {
            array_pop($this->pending);
        }

        $this->dispatcher?->dispatch(new AccessPolicyEvent($accessPolicy, $outcome, $parent));

        if (!$this->pending) {
            $this->dispatcher?->dispatch(new AccessQueryEvent($outcome->decision, $context->origin));
        }

        return $outcome;
    }

    private function findHandler(AccessPolicyInterface $accessPolicy): AccessPolicyHandlerInterface
    {
        $this->handlersList ??= \is_array($this->handlers) ? array_values($this->handlers) : iterator_to_array($this->handlers, false);

        foreach ($this->handlersList as $handler) {
            if ($handler->supports($accessPolicy)) {
                return $handler;
            }
        }

        throw new UnsupportedAccessPolicyException(\sprintf('No handler supports the "%s" access policy.', $accessPolicy::class));
    }
}
