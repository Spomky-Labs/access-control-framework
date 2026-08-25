<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Workflow;

use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Requester\RequesterProviderInterface;
use AccessControl\Voter\Expression\ExpressionVoter;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\Workflow\Event\GuardEvent;
use Symfony\Component\Workflow\EventListener\GuardExpression;
use Symfony\Component\Workflow\TransitionBlocker;

/**
 * Blocks a workflow transition whose guard expression does not hold, for applications that have no
 * Security.
 *
 * Workflow's own guard listener is typed on four contracts of Security, two of which belong to the
 * authorization half and will move here, and its expression language extends Security's. Registering
 * this bundle swaps the listener rather than touching any of that: Workflow keeps working exactly as
 * it does, and the day authorization leaves Security the replacement already exists and is tested.
 *
 * An application that has SecurityBundle keeps Workflow's listener, which already asks this
 * component through the decision manager. Only the shape with no Security at all is served here.
 *
 * The expression is not put to the decision manager but to the expression voter alone. Going through
 * the manager would offer the guard to every other voter and combine the answers with the configured
 * strategy, so a permissive application voter could grant a transition whose expression is false.
 * A guard blocks unless its own expression holds, which is what Workflow means by the word.
 */
final readonly class GuardListener
{
    /**
     * @param array<string, GuardExpression|string|list<GuardExpression|string>> $configuration
     */
    public function __construct(
        private array $configuration,
        private ExpressionVoter $expressionVoter,
        private RequesterProviderInterface $requesterProvider,
    ) {
    }

    public function onTransition(GuardEvent $event, string $eventName): void
    {
        if (! isset($this->configuration[$eventName])) {
            return;
        }

        foreach ((array) $this->configuration[$eventName] as $guard) {
            if ($guard instanceof GuardExpression) {
                if ($guard->getTransition() !== $event->getTransition()) {
                    continue;
                }

                $guard = $guard->getExpression();
            }

            $this->validateGuardExpression($event, $guard);
        }
    }

    private function validateGuardExpression(GuardEvent $event, string $expression): void
    {
        $accessRequest = new AccessRequest(
            $this->requesterProvider->getRequester(),
            new Expression($expression),
            $event->getSubject(),
        );

        if ($this->expressionVoter->vote($accessRequest)->decision === DecisionVote::ACCESS_GRANTED) {
            return;
        }

        $event->addTransitionBlocker(TransitionBlocker::createBlockedByExpressionGuardListener($expression));
    }
}
