<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use function is_array;

/**
 * PBAC: the rules live in a central repository, outside the code that enforces them.
 *
 * The voter is the decision point, the listeners are the enforcement points, and the repository
 * is the administration point. Matching rules are combined by letting denials win.
 */
final readonly class PolicyRepositoryVoter implements VoterInterface
{
    /**
     * @param list<PolicyRule> $rules
     */
    public function __construct(
        private array $rules,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return array_any($this->rules, fn ($rule) => $rule->attribute === $attribute);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! is_array($accessRequest->requester)) {
            return AccessOutcome::abstain('The requester carries no attributes.');
        }

        $permits = [];

        foreach ($this->rules as $rule) {
            if ($rule->attribute !== $accessRequest->attribute || ! $this->matches($rule, $accessRequest->requester)) {
                continue;
            }

            if (! $rule->permit) {
                return AccessOutcome::deny($rule->description);
            }

            $permits[] = $rule->description;
        }

        if (! $permits) {
            return AccessOutcome::abstain('No rule of the repository applies.');
        }

        return AccessOutcome::grant(implode(' ', $permits));
    }

    /**
     * @param array<string, mixed> $requester
     */
    private function matches(PolicyRule $rule, array $requester): bool
    {
        return array_all($rule->target, fn ($value, $name) => ! (($requester[$name] ?? null) !== $value));
    }
}
