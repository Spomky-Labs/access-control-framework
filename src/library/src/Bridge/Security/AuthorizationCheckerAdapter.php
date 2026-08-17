<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Security;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessDecision as AccessControlDecision;
use AccessControl\DecisionVote;
use AccessControl\Requester\RequesterProviderInterface;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\RequesterBoundChecker;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\OfflineTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\UserAuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Answers Security's authorization contracts on top of an AccessControlManager.
 *
 * This is the single seam through which Twig, AbstractController, ControllerHelper,
 * SecurityBundle's Security, Workflow's GuardListener and IsGrantedContext migrate: they all speak
 * to AuthorizationCheckerInterface and none of them has to change.
 *
 * The arrow points the right way round. Security's classes are used here, AccessControl is never
 * used by Security, which is what reconciles the independence of the component with a smooth
 * migration.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final readonly class AuthorizationCheckerAdapter implements AuthorizationCheckerInterface, UserAuthorizationCheckerInterface
{
    public function __construct(
        private AccessControlManagerInterface $accessControlManager,
        private RequesterProviderInterface $requesterProvider,
    ) {
    }

    /**
     * Security guarantees a token to its voters, standing in a NullToken for a missing or user less
     * one. Reproducing that here rather than in the manager keeps the component free of any notion
     * of token, while a requester that is not a token at all is left untouched, since the component
     * allows one and Security never had to consider the case.
     */
    public function isGranted(mixed $attribute, mixed $subject = null, ?AccessDecision $accessDecision = null): bool
    {
        $requester = $this->requesterProvider->getRequester();

        if (null === $requester || ($requester instanceof TokenInterface && !$requester->getUser())) {
            $requester = new NullToken();
        }

        return $this->check($requester, $attribute, $subject, $accessDecision);
    }

    /**
     * The very token Security builds, down to the anonymous class. Wrapping the user rather than
     * passing it bare is what makes the two stacks agree on authentication attributes: both then
     * refuse to answer them, an authentication state being meaningless offline.
     */
    public function isGrantedForUser(UserInterface $user, mixed $attribute, mixed $subject = null, ?AccessDecision $accessDecision = null): bool
    {
        $token = new class($user->getRoles()) extends AbstractToken implements OfflineTokenInterface {};
        $token->setUser($user);

        return $this->check($token, $attribute, $subject, $accessDecision);
    }

    /**
     * Binding the requester is what replaces the token stack Security needs: a nested question
     * carries its own requester instead of reading an ambient one.
     */
    private function check(mixed $requester, mixed $attribute, mixed $subject, ?AccessDecision $accessDecision): bool
    {
        $checker = new RequesterBoundChecker($this->accessControlManager, new StaticRequesterProvider($requester));
        $decision = $checker->decide($attribute, $subject);

        $granted = DecisionVote::ACCESS_GRANTED === $decision->decision;

        if (null !== $accessDecision) {
            $accessDecision->isGranted = $granted;
            $accessDecision->votes = $this->translateVotes($decision);
        }

        return $granted;
    }

    /**
     * The application's own voter rather than the adapter this bridge wrapped it in, which is what
     * Security reported before the switch and what a template asking who refused expects to read.
     *
     * @return list<Vote>
     */
    private function translateVotes(AccessControlDecision $decision): array
    {
        $votes = [];

        foreach ($decision->votes as $cast) {
            $voter = $cast->voter;
            $vote = new Vote();
            $vote->voter = $voter instanceof VoterAdapter ? $voter->voter::class : $voter::class;
            $vote->result = match ($cast->outcome->decision) {
                DecisionVote::ACCESS_GRANTED => VoterInterface::ACCESS_GRANTED,
                DecisionVote::ACCESS_DENIED => VoterInterface::ACCESS_DENIED,
                DecisionVote::ACCESS_ABSTAIN => VoterInterface::ACCESS_ABSTAIN,
            };

            if (null !== $cast->outcome->reason) {
                $vote->addReason($cast->outcome->reason);
            }

            $votes[] = $vote;
        }

        return $votes;
    }
}
