<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

/**
 * Always answers the same thing, so that a set of them separates one combining algorithm from
 * another. Two of these refusing against one granting is the shape that tells affirmative from
 * unanimous, from consensus and from priority; voters that agree tell nothing.
 */
class FixedVoter implements VoterInterface
{
    public function __construct(
        private readonly bool $granting,
    ) {
    }

    public function vote(TokenInterface $token, mixed $subject, array $attributes, ?Vote $vote = null): int
    {
        if (!\in_array('THING', $attributes, true)) {
            return self::ACCESS_ABSTAIN;
        }

        return $this->granting ? self::ACCESS_GRANTED : self::ACCESS_DENIED;
    }
}
