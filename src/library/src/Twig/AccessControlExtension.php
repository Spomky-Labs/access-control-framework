<?php

declare(strict_types=1);

namespace AccessControl\Twig;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\RequesterBoundChecker;
use AccessControl\Voter\ABAC\AuthenticationState;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Asks the access control questions a template may ask, in an application that has no Security.
 *
 * The function names are those Security's Twig extension already publishes, so a template moves
 * across without being rewritten. Only one of the two extensions ever answers a given function:
 * registering the bundle hands these two over to this one and leaves Security the rest.
 *
 * Field level access control is the one thing not carried across. It goes through symfony/acl,
 * whose FieldVote no voter of this component understands, so a field is refused loudly rather than
 * quietly denied.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final class AccessControlExtension extends AbstractExtension
{
    public function __construct(
        private readonly RequesterBoundChecker $accessChecker,
        private readonly AccessControlManagerInterface $accessControlManager,
    ) {
    }

    public function isGranted(mixed $attribute, mixed $subject = null, ?string $field = null): bool
    {
        self::rejectField($field, 'is_granted');

        return $this->accessChecker->isGranted($attribute, $subject);
    }

    /**
     * Deciding for someone other than the current requester is native here, an access request naming
     * its own requester. Security needs a dedicated contract for it.
     *
     * An authentication state is refused rather than answered, which is what Security does too, by
     * wrapping the user in an offline token its AuthenticatedVoter then rejects. That wrapping is
     * not reproducible here: the component accepts any requester, and a wrapper would hide it from
     * every voter that looks at its type. The invariant is therefore stated at the entry point,
     * where the question is asked, and the two stacks answer alike.
     */
    public function isGrantedForUser(mixed $user, mixed $attribute, mixed $subject = null, ?string $field = null): bool
    {
        self::rejectField($field, 'is_granted_for_user');

        return $this->decisionForUser($user, $attribute, $subject)->isGranted();
    }

    /**
     * The whole decision rather than its verdict, so that a template can say why and not only
     * whether. Security publishes access_decision() for this; that one hands back an object of its
     * own, which this component has no counterpart for, so it stays Security's and this is the
     * question asked in this component's words.
     *
     * The name is not access_decision(): the two return different shapes, and a function whose
     * return type depended on which bundles are installed would be a trap. A template that wants
     * this component's vocabulary asks for it by name, and both live side by side during a
     * migration.
     */
    public function decision(mixed $attribute, mixed $subject = null): AccessDecision
    {
        return $this->accessChecker->decide($attribute, $subject);
    }

    public function decisionForUser(mixed $user, mixed $attribute, mixed $subject = null): AccessDecision
    {
        $state = \is_string($attribute) ? AuthenticationState::fromValue($attribute) : null;

        if (null !== $state && AuthenticationState::PUBLIC_ACCESS !== $state) {
            throw new \InvalidArgumentException(\sprintf('Cannot decide on the "%s" authentication state for a requester other than the current one.', $attribute));
        }

        return $this->accessControlManager->decide(new AccessRequest($user, $attribute, $subject));
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('is_granted', $this->isGranted(...)),
            new TwigFunction('is_granted_for_user', $this->isGrantedForUser(...)),
            new TwigFunction('access_control_decision', $this->decision(...)),
            new TwigFunction('access_control_decision_for_user', $this->decisionForUser(...)),
        ];
    }

    /**
     * Answering false would be a denial the template cannot tell from a real one, and answering true
     * would be worse.
     */
    private static function rejectField(?string $field, string $function): void
    {
        if (null !== $field) {
            throw new \LogicException(\sprintf('Passing a $field to the "%s()" function is field level access control, which goes through symfony/acl and is not carried over by the AccessControl component.', $function));
        }
    }
}
