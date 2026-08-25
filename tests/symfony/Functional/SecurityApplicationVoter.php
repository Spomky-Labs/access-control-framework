<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use function in_array;

/**
 * The voter an application writes, untouched by the migration. It must keep being consulted once
 * the decision manager is pointed at the component, which is what the bridge is for.
 */
class SecurityApplicationVoter implements VoterInterface, CacheableVoterInterface
{
    public function supportsAttribute(string $attribute): bool
    {
        return $attribute === 'APP_PERMISSION';
    }

    public function supportsType(string $subjectType): bool
    {
        return true;
    }

    public function vote(TokenInterface $token, mixed $subject, array $attributes, ?Vote $vote = null): int
    {
        if (! in_array('APP_PERMISSION', $attributes, true)) {
            return self::ACCESS_ABSTAIN;
        }

        if ($token->getUserIdentifier() === 'alice') {
            $vote?->addReason('Alice carries the application permission.');

            return self::ACCESS_GRANTED;
        }

        $vote?->addReason('Only Alice carries the application permission.');

        return self::ACCESS_DENIED;
    }
}
