<?php

declare(strict_types=1);

namespace AccessControl\Tests;

use AccessControl\AccessControlManager;
use AccessControl\ExpressionLanguage;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\FirstApplicableStrategy;
use AccessControl\Strategy\MajorityStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\FakeEventDispatcher;
use AccessControl\Tests\Fixtures\FakeTokenStorage;
use AccessControl\Voter\ABAC\AuthenticatedVoter;
use AccessControl\Voter\Expression\ExpressionVoter;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleHierarchyInterface;
use AccessControl\Voter\RBAC\RoleVoter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

abstract class StrategyTestCase extends TestCase
{
    private ?AccessControlManager $accessControlManager = null;

    private ?FakeEventDispatcher $eventDispatcher = null;

    private ?TokenStorageInterface $tokenStorage = null;

    protected function getTokenStorage(): TokenStorageInterface
    {
        if ($this->tokenStorage === null) {
            $this->tokenStorage = new FakeTokenStorage();
        }

        return $this->tokenStorage;
    }

    /**
     * The expression voter needs the manager it is registered into, so the list is walked lazily:
     * by the time a voter is built, the manager exists.
     */
    protected function getAccessControlManager(): AccessControlManager
    {
        if ($this->accessControlManager === null) {
            $manager = null;
            $roleHierarchy = $this->getRoleHierarchy();

            $voters = (static function () use (&$manager, $roleHierarchy) {
                yield new ExpressionVoter(new ExpressionLanguage(), $manager, new AuthenticationTrustResolver(), $roleHierarchy);
                yield new RoleVoter($roleHierarchy);
                yield new AuthenticatedVoter(new AuthenticationTrustResolver());
            })();

            $this->accessControlManager = $manager = new AccessControlManager(
                [
                    new PermitOverridesStrategy(),
                    new MajorityStrategy(),
                    new DenyOverridesStrategy(),
                    new FirstApplicableStrategy(),
                ],
                $voters,
                dispatcher: $this->getEventDispatcher(),
            );
        }

        return $this->accessControlManager;
    }

    protected function getEventDispatcher(): FakeEventDispatcher
    {
        if ($this->eventDispatcher === null) {
            $this->eventDispatcher = new FakeEventDispatcher();
        }

        return $this->eventDispatcher;
    }

    protected function getRoleHierarchy(): RoleHierarchyInterface
    {
        return new RoleHierarchy([
            'ROLE_ADMIN' => ['ROLE_USER'],
            'ROLE_SUPER_ADMIN' => ['ROLE_ADMIN', 'ROLE_ALLOWED_TO_SWITCH'],
        ]);
    }
}
