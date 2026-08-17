<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\Authorization\Strategy\AccessDecisionStrategyInterface;

/**
 * The combining algorithm an application writes and names through
 * security.access_decision_manager.strategy_service. Refusing whatever the voters said is what
 * makes it impossible to confuse with any of the four Symfony ships.
 */
class AlwaysDenyingStrategy implements AccessDecisionStrategyInterface
{
    public function decide(\Traversable $results, ?AccessDecision $accessDecision = null): bool
    {
        return false;
    }
}
