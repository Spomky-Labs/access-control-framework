<?php

declare(strict_types=1);

namespace AccessControl\Handler;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Attribute\All;
use AccessControl\DecisionVote;
use function assert;

/**
 * @experimental
 */
final readonly class AllHandler implements AccessPolicyHandlerInterface
{
    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof All;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        assert($accessPolicy instanceof All);

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

        return AccessOutcome::grant('Every nested access policy granted access.');
    }
}
