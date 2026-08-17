<?php

declare(strict_types=1);

namespace AccessControl\Tests\Model;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessDecision;
use AccessControl\AccessEnvironment;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\MajorityStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\Model\AttributeBasedVoter;
use AccessControl\Tests\Fixtures\Model\ClearedRequester;
use AccessControl\Tests\Fixtures\Model\ContextVoter;
use AccessControl\Tests\Fixtures\Model\Document;
use AccessControl\Tests\Fixtures\Model\IdentityVoter;
use AccessControl\Tests\Fixtures\Model\MandatoryAccessVoter;
use AccessControl\Tests\Fixtures\Model\OwnershipVoter;
use AccessControl\Tests\Fixtures\Model\PolicyRepositoryVoter;
use AccessControl\Tests\Fixtures\Model\PolicyRule;
use AccessControl\Tests\Fixtures\Model\RelationshipVoter;
use AccessControl\Tests\Fixtures\Model\ScheduleRuleVoter;
use AccessControl\Tests\Fixtures\Model\SecurityLabel;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleVoter;
use AccessControl\VoterInterface;
use Symfony\Component\Clock\MockClock;

/**
 * Each of the established access control models is expressed with the shipped interfaces only.
 *
 * The voters live in Tests/Fixtures/Model and none of them required a change to the component:
 * the requester, the attribute and the subject are all mixed, and the environment travels in the
 * environment bag, which is what lets a model bring its own vocabulary.
 */
class AccessControlModelsTest extends TestCase
{
    public function testDiscretionaryAccessControl()
    {
        $document = new Document('budget', owner: 'alice', grants: ['read' => ['bob']]);
        $voters = [new OwnershipVoter()];

        $this->assertGranted($voters, new AccessRequest('alice', 'read', $document));
        $this->assertGranted($voters, new AccessRequest('alice', 'write', $document));
        $this->assertGranted($voters, new AccessRequest('bob', 'read', $document));
        $this->assertDenied($voters, new AccessRequest('bob', 'write', $document));
        $this->assertDenied($voters, new AccessRequest('carol', 'read', $document));
    }

    public function testMandatoryAccessControl()
    {
        $secret = new Document('plans', classification: new SecurityLabel(2));
        $internal = new Document('memo', classification: new SecurityLabel(1));
        $officer = new ClearedRequester('officer', new SecurityLabel(2));
        $clerk = new ClearedRequester('clerk', new SecurityLabel(1));
        $voters = [new MandatoryAccessVoter()];

        $this->assertGranted($voters, new AccessRequest($officer, 'read', $secret));
        $this->assertGranted($voters, new AccessRequest($officer, 'read', $internal));
        $this->assertDenied($voters, new AccessRequest($clerk, 'read', $secret));

        $this->assertGranted($voters, new AccessRequest($clerk, 'write', $secret));
        $this->assertDenied($voters, new AccessRequest($officer, 'write', $internal));
    }

    public function testLatticeBasedAccessControl()
    {
        $nuclear = new Document('reactor', classification: new SecurityLabel(2, ['NUCLEAR']));
        $crypto = new Document('keys', classification: new SecurityLabel(2, ['CRYPTO']));
        $both = new ClearedRequester('director', new SecurityLabel(2, ['NUCLEAR', 'CRYPTO']));
        $nuclearOnly = new ClearedRequester('engineer', new SecurityLabel(2, ['NUCLEAR']));
        $voters = [new MandatoryAccessVoter()];

        $this->assertGranted($voters, new AccessRequest($both, 'read', $nuclear));
        $this->assertGranted($voters, new AccessRequest($both, 'read', $crypto));
        $this->assertGranted($voters, new AccessRequest($nuclearOnly, 'read', $nuclear));
        $this->assertDenied($voters, new AccessRequest($nuclearOnly, 'read', $crypto));
    }

    public function testLatticeLabelsMayBeIncomparable()
    {
        $nuclearOnly = new ClearedRequester('engineer', new SecurityLabel(2, ['NUCLEAR']));
        $crypto = new Document('keys', classification: new SecurityLabel(2, ['CRYPTO']));
        $voters = [new MandatoryAccessVoter()];

        $this->assertDenied($voters, new AccessRequest($nuclearOnly, 'read', $crypto));
        $this->assertDenied($voters, new AccessRequest($nuclearOnly, 'write', $crypto));
    }

    public function testRoleBasedAccessControl()
    {
        $voters = [new RoleVoter(new RoleHierarchy(['ROLE_ADMIN' => ['ROLE_USER']]))];
        $admin = new StandaloneRequester(['ROLE_ADMIN']);

        $this->assertGranted($voters, new AccessRequest($admin, 'ROLE_ADMIN'));
        $this->assertGranted($voters, new AccessRequest($admin, 'ROLE_USER'));
        $this->assertDenied($voters, new AccessRequest($admin, 'ROLE_SUPER_ADMIN'));
    }

    public function testAttributeBasedAccessControl()
    {
        $requester = ['department' => 'sales', 'seniority' => 3];
        $ownDepartment = ['department' => 'sales'];
        $otherDepartment = ['department' => 'legal'];
        $voters = [new AttributeBasedVoter()];

        $this->assertGranted($voters, new AccessRequest($requester, 'read', $ownDepartment, new AccessEnvironment(['network' => 'corporate'])));
        $this->assertDenied($voters, new AccessRequest($requester, 'read', $otherDepartment, new AccessEnvironment(['network' => 'corporate'])));
        $this->assertDenied($voters, new AccessRequest($requester, 'read', $ownDepartment, new AccessEnvironment(['network' => 'public'])));
    }

    public function testRelationshipBasedAccessControl()
    {
        $voters = [new RelationshipVoter([
            'doc:roadmap#viewer' => ['user:alice', 'group:product#member'],
            'group:product#member' => ['user:bob', 'group:design#member'],
            'group:design#member' => ['user:carol'],
        ])];

        $this->assertGranted($voters, new AccessRequest('user:alice', 'viewer', 'doc:roadmap'));
        $this->assertGranted($voters, new AccessRequest('user:bob', 'viewer', 'doc:roadmap'));
        $this->assertGranted($voters, new AccessRequest('user:carol', 'viewer', 'doc:roadmap'));
        $this->assertDenied($voters, new AccessRequest('user:dave', 'viewer', 'doc:roadmap'));
    }

    public function testRelationshipTraversalSurvivesACycle()
    {
        $voters = [new RelationshipVoter([
            'group:a#member' => ['group:b#member'],
            'group:b#member' => ['group:a#member'],
        ])];

        $this->assertDenied($voters, new AccessRequest('user:alice', 'member', 'group:a'));
    }

    public function testContextBasedAccessControl()
    {
        $voters = [new ContextVoter()];

        $this->assertGranted($voters, new AccessRequest('alice', 'read', null, new AccessEnvironment(['trusted_device' => true, 'risk' => 0.1])));
        $this->assertDenied($voters, new AccessRequest('alice', 'read', null, new AccessEnvironment(['trusted_device' => true, 'risk' => 0.9])));
        $this->assertDenied($voters, new AccessRequest('alice', 'read', null, new AccessEnvironment(['trusted_device' => false, 'risk' => 0.1])));
    }

    public function testPolicyBasedAccessControl()
    {
        $voters = [new PolicyRepositoryVoter([
            new PolicyRule('export', ['department' => 'finance'], true, 'Finance may export.'),
            new PolicyRule('export', ['contractor' => true], false, 'Contractors may never export.'),
        ])];

        $this->assertGranted($voters, new AccessRequest(['department' => 'finance'], 'export'));
        $this->assertDenied($voters, new AccessRequest(['department' => 'sales'], 'export'));
        $this->assertDenied($voters, new AccessRequest(['department' => 'finance', 'contractor' => true], 'export'));
    }

    /**
     * The rule reads the clock rather than the environment bag, so that no entry point may disable it
     * by omission. A rule that abstains on a missing piece of environment fails open.
     */
    public function testRuleBasedAccessControl()
    {
        $document = new Document('budget', owner: 'alice');
        $accessRequest = new AccessRequest('alice', 'read', $document);

        $this->assertGranted([new OwnershipVoter(), new ScheduleRuleVoter(new MockClock('2026-08-01 14:00:00'))], $accessRequest, 'deny_overrides');
        $this->assertDenied([new OwnershipVoter(), new ScheduleRuleVoter(new MockClock('2026-08-01 22:00:00'))], $accessRequest, 'deny_overrides');
    }

    public function testIdentityBasedAccessControl()
    {
        $voters = [new IdentityVoter(['deploy' => ['alice', 'bob']])];

        $this->assertGranted($voters, new AccessRequest('alice', 'deploy'));
        $this->assertDenied($voters, new AccessRequest('carol', 'deploy'));
    }

    /**
     * A mandatory rule only binds under a strategy that lets a denial win. Under the permit
     * overrides strategy, the default one, the discretionary grant carries the decision and the
     * mandatory denial is bypassed.
     */
    public function testAMandatoryDenialOverridesADiscretionaryGrant()
    {
        $document = new Document('plans', owner: 'alice', classification: new SecurityLabel(2));
        $undercleared = new ClearedRequester('alice', new SecurityLabel(1));
        $accessRequest = new AccessRequest($undercleared, 'read', $document);
        $voters = [new OwnershipVoter(), new MandatoryAccessVoter()];

        $this->assertDenied($voters, $accessRequest, 'deny_overrides');
        $this->assertGranted($voters, $accessRequest, 'permit_overrides');
    }

    public function testModelsRegisteredTogetherDoNotInterfere()
    {
        $document = new Document('budget', owner: 'alice');
        $voters = [
            new OwnershipVoter(),
            new MandatoryAccessVoter(),
            new RoleVoter(),
            new IdentityVoter(['deploy' => ['bob']]),
            new RelationshipVoter(['doc:roadmap#viewer' => ['user:carol']]),
        ];

        $this->assertGranted($voters, new AccessRequest('alice', 'read', $document), 'deny_overrides');
        $this->assertGranted($voters, new AccessRequest('bob', 'deploy'), 'deny_overrides');
        $this->assertGranted($voters, new AccessRequest('user:carol', 'viewer', 'doc:roadmap'), 'deny_overrides');
        $this->assertGranted($voters, new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'), 'deny_overrides');
    }

    /**
     * @param list<VoterInterface> $voters
     */
    private function assertGranted(array $voters, AccessRequest $accessRequest, string $strategy = 'permit_overrides'): void
    {
        $decision = $this->decide($voters, $accessRequest, $strategy);

        $this->assertSame(DecisionVote::ACCESS_GRANTED, $decision->decision, $decision->reason ?? '');
    }

    /**
     * @param list<VoterInterface> $voters
     */
    private function assertDenied(array $voters, AccessRequest $accessRequest, string $strategy = 'permit_overrides'): void
    {
        $decision = $this->decide($voters, $accessRequest, $strategy);

        $this->assertSame(DecisionVote::ACCESS_DENIED, $decision->decision, $decision->reason ?? '');
    }

    /**
     * @param list<VoterInterface> $voters
     */
    private function decide(array $voters, AccessRequest $accessRequest, string $strategy): AccessDecision
    {
        $accessControlManager = new AccessControlManager(
            [new PermitOverridesStrategy(), new DenyOverridesStrategy(), new MajorityStrategy()],
            $voters,
        );

        return $accessControlManager->decide($accessRequest, $strategy);
    }
}
