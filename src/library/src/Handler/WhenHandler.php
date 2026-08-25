<?php

declare(strict_types=1);

namespace AccessControl\Handler;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Attribute\When;
use AccessControl\DecisionVote;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;
use function assert;
use function sprintf;

final readonly class WhenHandler implements AccessPolicyHandlerInterface
{
    public function __construct(
        private ExpressionLanguage $expressionLanguage,
    ) {
    }

    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof When;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        assert($accessPolicy instanceof When);

        if (! $this->expressionLanguage->evaluate($accessPolicy->condition, $this->getVariables($context))) {
            return AccessOutcome::abstain(sprintf('The condition (%s) does not hold.', $accessPolicy->condition));
        }

        $granted = 0;

        foreach ($accessPolicy->accessPolicies as $nested) {
            $outcome = $evaluator->evaluate($nested, $context);

            if ($outcome->decision === DecisionVote::ACCESS_DENIED) {
                return $outcome;
            }

            if ($outcome->decision === DecisionVote::ACCESS_GRANTED) {
                ++$granted;
            }
        }

        if ($granted === 0) {
            return AccessOutcome::abstain('No nested access policy applied.');
        }

        return AccessOutcome::grant('The condition holds and every nested access policy granted access.');
    }

    /**
     * @return array<string, mixed>
     */
    private function getVariables(AccessPolicyContext $context): array
    {
        return [
            ...$context->environment,
            'requester' => $context->requester,
            'arguments' => $context->arguments,
        ];
    }
}
