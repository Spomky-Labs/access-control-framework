<?php

declare(strict_types=1);

namespace AccessControl\Handler;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\DecisionVote;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final readonly class AtLeastOneOfHandler implements AccessPolicyHandlerInterface
{
    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof AtLeastOneOf;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        \assert($accessPolicy instanceof AtLeastOneOf);

        $denied = null;

        foreach ($accessPolicy->accessPolicies as $nested) {
            $outcome = $evaluator->evaluate($nested, $context);

            if (DecisionVote::ACCESS_GRANTED === $outcome->decision) {
                return $outcome;
            }

            $denied ??= DecisionVote::ACCESS_DENIED === $outcome->decision ? $outcome : null;
        }

        return $denied ?? AccessOutcome::abstain('No nested access policy applied.');
    }
}
