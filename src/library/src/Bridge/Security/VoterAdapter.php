<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Security;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface as SecurityVoterInterface;
use function is_object;
use function is_string;
use function sprintf;

/**
 * Lets a voter written against Security answer questions asked to this component.
 *
 * This is the piece the whole migration rests on. Every application has voters extending
 * Security's Voter, and without this they would simply stop being consulted the day the decision
 * manager is pointed at the component: no error, no deprecation, just access rules that quietly no
 * longer apply. Which is the worst failure an access control system can have.
 */
final readonly class VoterAdapter implements VoterInterface
{
    public function __construct(
        /**
         * Public so that the profiler can name it. Wrapped, an application voter would appear as
         * five identical adapters in the panel, and "are my voters still consulted" is the one
         * question a migration asks.
         */
        public SecurityVoterInterface $voter,
    ) {
    }

    /**
     * Security answers this on strings only. Anything else has to be offered to the voter, which
     * decides for itself inside vote().
     */
    public function supportsAttribute(mixed $attribute): bool
    {
        if (! $this->voter instanceof CacheableVoterInterface || ! is_string($attribute)) {
            return true;
        }

        return $this->voter->supportsAttribute($attribute);
    }

    public function supportsSubject(mixed $subject): bool
    {
        if (! $this->voter instanceof CacheableVoterInterface) {
            return true;
        }

        return $this->voter->supportsType(is_object($subject) ? $subject::class : get_debug_type($subject));
    }

    /**
     * A voter of Security is typed on a token and cannot be handed anything else, so a requester of
     * another kind leaves it with nothing to say rather than with an error.
     */
    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! $accessRequest->requester instanceof TokenInterface) {
            return AccessOutcome::abstain(sprintf('"%s" only votes on a security token.', $this->voter::class));
        }

        $vote = new Vote();
        $result = $this->voter->vote($accessRequest->requester, $accessRequest->subject, [$accessRequest->attribute], $vote);
        $reason = $vote->reasons ? implode(' ', $vote->reasons) : null;

        return match ($result) {
            SecurityVoterInterface::ACCESS_GRANTED => AccessOutcome::grant($reason),
            SecurityVoterInterface::ACCESS_DENIED => AccessOutcome::deny($reason),
            default => AccessOutcome::abstain($reason),
        };
    }
}
