<?php

declare(strict_types=1);

namespace AccessControl\Handler;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\DecisionVote;
use function assert;

final readonly class AtLeastOneOfHandler implements AccessPolicyHandlerInterface
{
    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof AtLeastOneOf;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        assert($accessPolicy instanceof AtLeastOneOf);

        $denied = null;

        foreach ($accessPolicy->accessPolicies as $nested) {
            $outcome = $evaluator->evaluate($nested, $context);

            if ($outcome->decision === DecisionVote::ACCESS_GRANTED) {
                return $outcome;
            }

            $denied ??= $outcome->decision === DecisionVote::ACCESS_DENIED ? $outcome : null;
        }

        return $denied ?? AccessOutcome::abstain('No nested access policy applied.');
    }
}
