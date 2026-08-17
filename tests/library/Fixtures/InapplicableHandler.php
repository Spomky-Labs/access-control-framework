<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Handler\AccessPolicyHandlerInterface;

final readonly class InapplicableHandler implements AccessPolicyHandlerInterface
{
    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof Inapplicable;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        return AccessOutcome::abstain('The access policy does not apply here.');
    }
}
