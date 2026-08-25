<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Security;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessDecision as AccessControlDecision;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Event\AccessQueryEvent;
use AccessControl\VoterInterface as AccessControlVoterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use function is_bool;

/**
 * Answers Security's decision contract on top of an AccessControlManager.
 *
 * This is the widest seam of the migration. Everything Security decides goes through
 * security.access.decision_manager: the access_control rules of the firewall, the authorization
 * checker and therefore #[IsGranted], the Twig functions, the workflow guards. Pointing this one
 * service at the component moves all of them at once, and an application changes not a line of its
 * security.yaml.
 *
 * The attributes of a call are combined by letting any grant win, which is what Security does
 * inside each of its voters: a rule naming several roles is satisfied by any one of them.
 */
final readonly class AccessDecisionManagerAdapter implements AccessDecisionManagerInterface
{
    /**
     * Everything Security asks arrives here, so the origin says no more than that. It is still worth
     * recording: without it, a rule naming several roles reads as several unrelated questions.
     */
    private const string ORIGIN = 'security.access.decision_manager';

    public function __construct(
        private AccessControlManagerInterface $accessControlManager,
        private ?string $strategy = null,
        private ?EventDispatcherInterface $dispatcher = null,
        /**
         * What to report as the combining algorithm, which Security fills and templates read. Not
         * the same string as the one above: that one names the algorithm to use in this component's
         * vocabulary, this one is the word the application wrote, "unanimous" rather than
         * "deny_overrides", so a template does not start reading a translation of itself.
         */
        private ?string $strategyName = null,
    ) {
    }

    /**
     * The out parameter is filled in full, verdict, votes and algorithm alike. Left with a null
     * strategy, access_decision().strategy went from naming an algorithm to saying nothing at all
     * the day the bundle was installed, which is the kind of quiet loss this bridge exists to avoid.
     */
    public function decide(TokenInterface $token, array $attributes, mixed $object = null, bool|AccessDecision|null $accessDecision = null, bool $allowMultipleAttributes = false): bool
    {
        if (is_bool($accessDecision)) {
            $accessDecision = null;
        }

        $granted = false;
        $votes = [];

        foreach ($attributes as $attribute) {
            $decision = $this->accessControlManager->decide(new AccessRequest($token, $attribute, $object), $this->strategy);
            $votes = [...$votes, ...$this->translateVotes($decision)];

            if ($decision->decision === DecisionVote::ACCESS_GRANTED) {
                $granted = true;
            }
        }

        if ($accessDecision !== null) {
            $accessDecision->isGranted = $granted;
            $accessDecision->votes = $votes;
            $accessDecision->strategy = $this->strategyName;
        }

        $this->dispatcher?->dispatch(new AccessQueryEvent($granted ? DecisionVote::ACCESS_GRANTED : DecisionVote::ACCESS_DENIED, self::ORIGIN));

        return $granted;
    }

    /**
     * @return list<Vote>
     */
    private function translateVotes(AccessControlDecision $decision): array
    {
        $votes = [];

        foreach ($decision->votes as $cast) {
            $vote = new Vote();
            $vote->voter = self::nameOf($cast->voter);
            $vote->result = match ($cast->outcome->decision) {
                DecisionVote::ACCESS_GRANTED => VoterInterface::ACCESS_GRANTED,
                DecisionVote::ACCESS_DENIED => VoterInterface::ACCESS_DENIED,
                DecisionVote::ACCESS_ABSTAIN => VoterInterface::ACCESS_ABSTAIN,
            };

            if ($cast->outcome->reason !== null) {
                $vote->addReason($cast->outcome->reason);
            }

            $votes[] = $vote;
        }

        return $votes;
    }

    /**
     * The application's own voter rather than the adapter this bridge wrapped it in, which is what
     * Security reported before the switch and what a template asking who refused expects to read.
     */
    private static function nameOf(AccessControlVoterInterface $voter): string
    {
        return $voter instanceof VoterAdapter ? $voter->voter::class : $voter::class;
    }
}
