<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;

/**
 * The decision manager an application names through security.access_decision_manager.service.
 * Refusing whatever the voters said is what makes it impossible to confuse with anything else:
 * a granting voter under the affirmative default would otherwise grant.
 */
class AlwaysDenyingDecisionManager implements AccessDecisionManagerInterface
{
    public function decide(TokenInterface $token, array $attributes, mixed $object = null, ?AccessDecision $accessDecision = null): bool
    {
        return false;
    }
}
