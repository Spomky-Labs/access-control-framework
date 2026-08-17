<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\DecisionVote;
use AccessControl\Handler\AccessPolicyHandlerInterface;

final readonly class NotHandler implements AccessPolicyHandlerInterface
{
    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof Not;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        \assert($accessPolicy instanceof Not);

        foreach ($accessPolicy->accessPolicies as $nested) {
            $outcome = $evaluator->evaluate($nested, $context);

            if (DecisionVote::ACCESS_GRANTED === $outcome->decision) {
                return AccessOutcome::deny('A negated access policy granted access.');
            }
        }

        return AccessOutcome::grant('No negated access policy granted access.');
    }
}
