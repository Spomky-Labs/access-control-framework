<?php

declare(strict_types=1);

namespace AccessControl\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * Access rules in declaration order, the first match winning.
 */
class AccessRuleMap implements AccessRuleMapInterface
{
    /**
     * @var list<AccessRule>
     */
    private array $rules = [];

    /**
     * @param iterable<AccessRule> $rules
     */
    public function __construct(iterable $rules = [])
    {
        foreach ($rules as $rule) {
            $this->rules[] = $rule;
        }
    }

    public function add(AccessRule $rule): void
    {
        $this->rules[] = $rule;
    }

    public function getRule(Request $request): ?AccessRule
    {
        foreach ($this->rules as $rule) {
            if ($rule->requestMatcher->matches($request)) {
                return $rule;
            }
        }

        return null;
    }
}
