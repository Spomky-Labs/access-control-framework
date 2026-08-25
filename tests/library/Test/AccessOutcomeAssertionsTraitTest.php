<?php

declare(strict_types=1);

namespace AccessControl\Tests\Test;

use AccessControl\AccessControlManager;
use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Test\AccessOutcomeAssertionsTrait;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Voter\RBAC\RoleVoter;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

final class AccessOutcomeAssertionsTraitTest extends TestCase
{
    use AccessOutcomeAssertionsTrait;

    public function testTheAnswerOfASingleVoter(): void
    {
        $voter = new RoleVoter();
        $requester = new StandaloneRequester(['ROLE_ADMIN']);

        $this->assertAccessGranted($voter->vote(new AccessRequest($requester, 'ROLE_ADMIN')));
        $this->assertAccessDenied($voter->vote(new AccessRequest($requester, 'ROLE_SUPER_ADMIN')));
        $this->assertAccessAbstained($voter->vote(new AccessRequest($requester, 'not-a-role')));
    }

    public function testTheAnswerOfAWholeStack(): void
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new RoleVoter()]);
        $requester = new StandaloneRequester(['ROLE_ADMIN']);

        $this->assertAccessGranted($manager->decide(new AccessRequest($requester, 'ROLE_ADMIN')));
        $this->assertAccessDenied($manager->decide(new AccessRequest($requester, 'ROLE_SUPER_ADMIN')));
    }

    /**
     * The point of the trait: a bare comparison on the enum says the two values differ, which is
     * of no help. The reason the voter gave is what tells you why.
     */
    public function testTheFailureMessageCarriesTheReason(): void
    {
        try {
            $this->assertAccessGranted(AccessOutcome::deny('The user does not have the required role.'));
            static::fail('The assertion should have failed.');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('Failed asserting that access is granted.', $failure->getMessage());
            static::assertStringContainsString('Reason: The user does not have the required role.', $failure->getMessage());
        }
    }

    public function testAnAnswerWithoutAReasonSaysSo(): void
    {
        try {
            $this->assertAccessDenied(AccessOutcome::grant());
            static::fail('The assertion should have failed.');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('No reason was given.', $failure->getMessage());
        }
    }

    public function testACustomMessageWins(): void
    {
        try {
            $this->assertAccessGranted(AccessOutcome::deny('Ignored.'), 'The author should be allowed to edit.');
            static::fail('The assertion should have failed.');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('The author should be allowed to edit.', $failure->getMessage());
        }
    }
}
