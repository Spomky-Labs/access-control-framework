<?php

declare(strict_types=1);

namespace AccessControl\Voter;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\RequesterBoundChecker;
use AccessControl\VoterInterface;
use Closure;
use ReflectionFunction;
use function sprintf;

/**
 * Lets a closure be the attribute being voted on.
 *
 * The closure receives the access request and a checker bound to its requester, so that it may ask
 * a further question the same way an expression does.
 *
 * PHP forbids a closure in the arguments of an attribute, so this never comes from #[AccessPolicy]
 * written in source. It serves the programmatic path, which is the same limitation Security's
 * ClosureVoter lives with.
 */
final readonly class ClosureVoter implements VoterInterface
{
    public function __construct(
        private AccessControlManagerInterface $accessControlManager,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return $attribute instanceof Closure;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! $accessRequest->attribute instanceof Closure) {
            return AccessOutcome::abstain('The attribute is not a closure.');
        }

        $name = (new ReflectionFunction($accessRequest->attribute))->name;
        $checker = new RequesterBoundChecker($this->accessControlManager, new StaticRequesterProvider($accessRequest->requester), $accessRequest->environment);

        if (($accessRequest->attribute)($accessRequest, $checker)) {
            return AccessOutcome::grant(sprintf('Closure %s returned true.', $name));
        }

        return AccessOutcome::deny(sprintf('Closure %s returned false.', $name));
    }
}
