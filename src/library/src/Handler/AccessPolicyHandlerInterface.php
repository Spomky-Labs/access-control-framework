<?php

declare(strict_types=1);

namespace AccessControl\Handler;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;

interface AccessPolicyHandlerInterface
{
    public function supports(AccessPolicyInterface $accessPolicy): bool;

    /**
     * The evaluator is handed over so composite policies can process their children.
     */
    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome;
}
