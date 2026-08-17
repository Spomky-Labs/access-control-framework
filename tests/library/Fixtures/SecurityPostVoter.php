<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

/**
 * The Security counterpart of {@see PostVoter}, so that both stacks can answer the same question.
 *
 * Cacheable, as the Voter base class of Security is, so that an application voter is represented
 * the way applications actually write them.
 */
final class SecurityPostVoter implements VoterInterface, CacheableVoterInterface
{
    public function supportsAttribute(string $attribute): bool
    {
        return 'read' === $attribute;
    }

    public function supportsType(string $subjectType): bool
    {
        return Post::class === $subjectType;
    }

    public function vote(TokenInterface $token, mixed $subject, array $attributes, ?Vote $vote = null): int
    {
        if (!\in_array('read', $attributes, true) || !$subject instanceof Post) {
            return self::ACCESS_ABSTAIN;
        }

        return self::ACCESS_GRANTED;
    }
}
