<?php

declare(strict_types=1);

namespace AccessControl\Voter\Expression;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessEnvironment;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\Requester\Actor;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\RequesterBoundChecker;
use AccessControl\Voter\RBAC\RoleHierarchyInterface;
use AccessControl\Voter\RBAC\UserWithRoleInterface;
use AccessControl\VoterInterface;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use function is_object;
use function sprintf;

/**
 * @experimental
 */
final readonly class ExpressionVoter implements VoterInterface
{
    public function __construct(
        private ExpressionLanguage $expressionLanguage,
        private AccessControlManagerInterface $accessControlManager,
        private ?AuthenticationTrustResolverInterface $trustResolver = null,
        private ?RoleHierarchyInterface $roleHierarchy = null,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return $attribute instanceof Expression;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! $accessRequest->attribute instanceof Expression) {
            return AccessOutcome::abstain('The attribute is not an expression.');
        }

        if ($this->expressionLanguage->evaluate($accessRequest->attribute, $this->getVariables($accessRequest))) {
            return AccessOutcome::grant(sprintf('Expression (%s) is true.', $accessRequest->attribute));
        }

        return AccessOutcome::deny(sprintf('Expression (%s) is false.', $accessRequest->attribute));
    }

    /**
     * Three of these are published only when they mean something. The actor appears only when
     * somebody else is really asking, so that an expression naming it says what it means:
     * "an administrator, even while impersonating" is otherwise inexpressible without typing on a
     * Security token. The trust resolver appears only where there is one, and the request only when
     * it is the subject at hand.
     *
     * @return array{token: TokenInterface|null, user: mixed, object: mixed, subject: mixed, role_names: list<string>, auth_checker: RequesterBoundChecker, environment: AccessEnvironment, actor?: mixed, trust_resolver?: AuthenticationTrustResolverInterface, request?: Request}
     */
    private function getVariables(AccessRequest $accessRequest): array
    {
        $token = $accessRequest->requester instanceof TokenInterface ? $accessRequest->requester : null;
        $user = $token !== null ? $token->getUser() : $accessRequest->requester;
        $roleNames = [];
        if ($token !== null) {
            $roleNames = $token->getRoleNames();
        } elseif ($user instanceof UserWithRoleInterface || (is_object($user) && method_exists($user, 'getRoles'))) {
            $roleNames = $user->getRoles();
        }

        if ($this->roleHierarchy !== null) {
            $roleNames = $this->roleHierarchy->getReachableRoleNames($roleNames);
        }

        $variables = [
            'token' => $token,
            'user' => $user,
            'object' => $accessRequest->subject,
            'subject' => $accessRequest->subject,
            'role_names' => $roleNames,
            'auth_checker' => new RequesterBoundChecker($this->accessControlManager, new StaticRequesterProvider($accessRequest->requester), $accessRequest->environment),
            'environment' => $accessRequest->environment,
        ];

        if (null !== $actor = Actor::of($accessRequest->requester)) {
            $variables['actor'] = $actor;
        }

        if ($this->trustResolver !== null) {
            $variables['trust_resolver'] = $this->trustResolver;
        }

        if ($accessRequest->subject instanceof Request) {
            $variables['request'] = $accessRequest->subject;
        }

        return $variables;
    }
}
