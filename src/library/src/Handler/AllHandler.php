<?php

declare(strict_types=1);

namespace AccessControl\Handler;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Attribute\All;
use AccessControl\DecisionVote;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
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
        \assert($accessPolicy instanceof All);

        $granted = 0;

        foreach ($accessPolicy->accessPolicies as $nested) {
            $outcome = $evaluator->evaluate($nested, $context);

            if (DecisionVote::ACCESS_DENIED === $outcome->decision) {
                return $outcome;
            }

            if (DecisionVote::ACCESS_GRANTED === $outcome->decision) {
                ++$granted;
            }
        }

        if (0 === $granted) {
            return AccessOutcome::abstain('No nested access policy applied.');
        }

        return AccessOutcome::grant('Every nested access policy granted access.');
    }
}
