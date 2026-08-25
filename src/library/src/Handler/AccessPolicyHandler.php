<?php

declare(strict_types=1);

namespace AccessControl\Handler;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessEnvironment;
use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\AccessRequest;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\AccessPolicyInterface;
use function assert;

/**
 * @experimental
 */
final readonly class AccessPolicyHandler implements AccessPolicyHandlerInterface
{
    public function __construct(
        private AccessControlManagerInterface $accessControlManager,
    ) {
    }

    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof AccessPolicy;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        assert($accessPolicy instanceof AccessPolicy);

        $accessRequest = new AccessRequest(
            $context->requester,
            $context->resolve($accessPolicy->attribute),
            $context->resolve($accessPolicy->subject),
            new AccessEnvironment([...$accessPolicy->environment, ...$context->environment]),
            $accessPolicy->allowIfAllAbstain,
        );

        $accessDecision = $this->accessControlManager->decide($accessRequest, $accessPolicy->strategy);

        return new AccessOutcome($accessDecision->decision, $accessDecision->reason);
    }
}
