<?php

declare(strict_types=1);

namespace AccessControl\Voter\ABAC;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\Requester\Actor;
use AccessControl\VoterInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\OfflineTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use function in_array;
use function is_string;

/**
 * @experimental
 */
final readonly class AuthenticatedVoter implements VoterInterface
{
    /**
     * The trust resolver is optional so that PUBLIC_ACCESS, the commonest attribute of an access
     * rule, is understood in an application that has no Security. Every other authentication state
     * is refused without one.
     */
    public function __construct(
        private ?AuthenticationTrustResolverInterface $authenticationTrustResolver = null,
    ) {
    }

    /**
     * The states are answered in an order that is itself a decision. PUBLIC_ACCESS and
     * IS_IMPERSONATOR come before the token guard: whether the page is public, and whether somebody
     * else is really asking, need neither a token nor a trust resolver, so they are the two states
     * that stay decidable without Security. Its own voters never had to place them, always holding
     * a token.
     *
     * Every state below is a degree of authentication, and nothing authenticates without Security.
     * Refusing rather than abstaining there is what keeps the answer fail-closed.
     */
    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $attribute = AuthenticationState::fromValue($accessRequest->attribute);
        if ($attribute === null) {
            return AccessOutcome::abstain('The attribute is not an authentication state.');
        }

        if ($attribute === AuthenticationState::PUBLIC_ACCESS) {
            return AccessOutcome::grant('Access granted to public access');
        }

        if ($attribute === AuthenticationState::IS_IMPERSONATOR && Actor::isActedFor($accessRequest->requester)) {
            return AccessOutcome::grant('Access granted by impersonator.');
        }

        if (! $accessRequest->requester instanceof TokenInterface) {
            return AccessOutcome::abstain('The requester is not an instance of TokenInterface.');
        }

        if ($accessRequest->requester instanceof OfflineTokenInterface) {
            throw new InvalidArgumentException('Cannot decide on authentication attributes when an offline token is used.');
        }

        if ($this->authenticationTrustResolver === null) {
            return AccessOutcome::deny('No authentication trust resolver is available.');
        }

        if ($attribute === AuthenticationState::IS_AUTHENTICATED_FULLY
            && $this->authenticationTrustResolver->isFullFledged($accessRequest->requester)) {
            return AccessOutcome::grant('Access granted by fully authenticated user.');
        }

        if ($attribute === AuthenticationState::IS_AUTHENTICATED_REMEMBERED
            && ($this->authenticationTrustResolver->isRememberMe($accessRequest->requester)
                || $this->authenticationTrustResolver->isFullFledged($accessRequest->requester))) {
            return AccessOutcome::grant('Access granted by remembered user.');
        }

        if ($attribute === AuthenticationState::IS_AUTHENTICATED && $this->authenticationTrustResolver->isAuthenticated($accessRequest->requester)) {
            return AccessOutcome::grant('Access granted by authenticated user.');
        }

        if ($attribute === AuthenticationState::IS_REMEMBERED && $this->authenticationTrustResolver->isRememberMe($accessRequest->requester)) {
            return AccessOutcome::grant('Access granted by remembered user.');
        }

        return AccessOutcome::deny('The user does not have the required authentication state.');
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return is_string($attribute) && in_array($attribute, AuthenticationState::caseNames(), true);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }
}
