<?php

declare(strict_types=1);

namespace AccessControl;

use AccessControl\Requester\RequesterProviderInterface;

/**
 * Answers a yes or no question on behalf of one requester, and one only.
 *
 * This is what lets a rule written as an expression or as a closure ask the system a further
 * question. The voter that runs the rule builds one per evaluation, over a provider holding the
 * requester of the access request being evaluated, so a nested question is bound to the question
 * that raised it rather than to an ambient state. That binding is the whole point: a checker that
 * resolved the requester itself would be a poorer AccessControlManager, and there is no need
 * for two of those.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final readonly class RequesterBoundChecker
{
    public function __construct(
        private AccessControlManagerInterface $accessControlManager,
        private RequesterProviderInterface $requesterProvider,
        private AccessEnvironment $environment = new AccessEnvironment(),
    ) {
    }

    public function isGranted(mixed $attribute, mixed $subject = null): bool
    {
        return DecisionVote::ACCESS_GRANTED === $this->decide($attribute, $subject)->decision;
    }

    /**
     * Same question, with the whole decision rather than its verdict alone.
     */
    public function decide(mixed $attribute, mixed $subject = null): AccessDecision
    {
        return $this->accessControlManager->decide(new AccessRequest($this->requesterProvider->getRequester(), $attribute, $subject, $this->environment));
    }
}
