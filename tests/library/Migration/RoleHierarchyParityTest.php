<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use AccessControl\AccessRequest;
use AccessControl\Bridge\Security\RoleHierarchyAdapter;
use AccessControl\Test\AccessOutcomeAssertionsTrait;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Voter\RBAC\RoleHierarchy;
use AccessControl\Voter\RBAC\RoleHierarchyInterface;
use AccessControl\Voter\RBAC\RoleVoter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Role\RoleHierarchy as SecurityRoleHierarchy;

/**
 * The component owns its role hierarchy, as the notion of role is meant to leave Security and a
 * service of SecurityBundle cannot be leaned on. The two implementations therefore coexist for the
 * length of the migration, and this is what keeps them saying the same thing.
 *
 * The implementations differ inside: Security walks its list with an internal pointer, this one
 * uses a queue and a set of what it has already reached. Only the answers have to match.
 */
final class RoleHierarchyParityTest extends TestCase
{
    use AccessOutcomeAssertionsTrait;

    /**
     * The hierarchy of Security's own test for this method, so the comparison is against what it
     * pins rather than against a case chosen to agree.
     */
    private const array ENCOMPASSING = [
        'ROLE_ADMIN' => ['ROLE_USER'],
        'ROLE_SUPER_ADMIN' => ['ROLE_ADMIN', 'ROLE_FOO'],
        'ROLE_USER' => ['ROLE_BAR'],
    ];

    public static function provideHierarchies(): iterable
    {
        yield 'flat' => [[], ['ROLE_USER']];
        yield 'one level' => [[
            'ROLE_ADMIN' => ['ROLE_USER'],
        ], ['ROLE_ADMIN']];
        yield 'transitive' => [[
            'ROLE_SUPER_ADMIN' => ['ROLE_ADMIN'],
            'ROLE_ADMIN' => ['ROLE_USER'],
        ], ['ROLE_SUPER_ADMIN']];
        yield 'several held roles' => [[
            'ROLE_ADMIN' => ['ROLE_USER'],
        ], ['ROLE_ADMIN', 'ROLE_EDITOR']];
        yield 'a role that reaches two' => [[
            'ROLE_ADMIN' => ['ROLE_USER', 'ROLE_EDITOR'],
        ], ['ROLE_ADMIN']];
        yield 'a diamond' => [
            [
                'ROLE_A' => ['ROLE_B', 'ROLE_C'],
                'ROLE_B' => ['ROLE_D'],
                'ROLE_C' => ['ROLE_D'],
            ],
            ['ROLE_A'],
        ];
        yield 'an unknown role' => [[
            'ROLE_ADMIN' => ['ROLE_USER'],
        ], ['ROLE_NOBODY']];
        yield 'a role naming itself' => [[
            'ROLE_ADMIN' => ['ROLE_ADMIN', 'ROLE_USER'],
        ], ['ROLE_ADMIN']];
        yield 'a cycle of two' => [[
            'ROLE_A' => ['ROLE_B'],
            'ROLE_B' => ['ROLE_A'],
        ], ['ROLE_A']];
        yield 'a cycle of three' => [[
            'ROLE_A' => ['ROLE_B'],
            'ROLE_B' => ['ROLE_C'],
            'ROLE_C' => ['ROLE_A'],
        ], ['ROLE_A']];
        yield 'nothing held' => [[
            'ROLE_ADMIN' => ['ROLE_USER'],
        ], []];
    }

    /**
     * @param array<string, list<string>> $hierarchy
     * @param list<string>                $roles
     */
    #[DataProvider('provideHierarchies')]
    public function testBothHierarchiesReachTheSameRoles(array $hierarchy, array $roles)
    {
        $security = new SecurityRoleHierarchy($hierarchy)
            ->getReachableRoleNames($roles);
        $accessControl = new RoleHierarchy($hierarchy)
            ->getReachableRoleNames($roles);

        sort($security);
        sort($accessControl);

        static::assertSame($security, $accessControl);
    }

    /**
     * A cycle is what a hand written traversal gets wrong, and Security tolerates it rather than
     * failing, so this component has to as well.
     */
    public function testACycleTerminates()
    {
        $hierarchy = new RoleHierarchy([
            'ROLE_A' => ['ROLE_B'],
            'ROLE_B' => ['ROLE_A'],
        ]);

        static::assertSame(['ROLE_A', 'ROLE_B'], $hierarchy->getReachableRoleNames(['ROLE_A']));
    }

    public function testAHeldRoleIsAlwaysReachable()
    {
        $hierarchy = new RoleHierarchy([]);

        static::assertSame(['ROLE_USER'], $hierarchy->getReachableRoleNames(['ROLE_USER']));
    }

    /**
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideHeldRoles(): iterable
    {
        yield 'the top of the tree' => [['ROLE_SUPER_ADMIN']];
        yield 'a role in the middle' => [['ROLE_ADMIN']];
        yield 'a role two levels down' => [['ROLE_USER']];
        yield 'a leaf' => [['ROLE_BAR']];
        yield 'the same role twice' => [['ROLE_SUPER_ADMIN', 'ROLE_SUPER_ADMIN']];
        yield 'two roles, one reaching the other' => [['ROLE_SUPER_ADMIN', 'ROLE_USER']];
        yield 'two leaves' => [['ROLE_BAR', 'ROLE_FOO']];
        yield 'a role the hierarchy never names' => [['ROLE_NOBODY']];
        yield 'nothing held' => [[]];
    }

    /**
     * The inverse lookup: which roles encompass these, transitively. Nothing in this component asks
     * it and nothing in Symfony asks Security's, but it is public API an application may have built
     * a query on, and a brick with no counterpart here cannot be deprecated there.
     *
     * @param list<string> $roles
     */
    #[DataProvider('provideHeldRoles')]
    public function testBothHierarchiesEncompassTheSameRoles(array $roles)
    {
        $security = new SecurityRoleHierarchy(self::ENCOMPASSING)->getParentRoleNames($roles);
        $accessControl = new RoleHierarchy(self::ENCOMPASSING)->getParentRoleNames($roles);

        sort($security);
        sort($accessControl);

        static::assertSame($security, $accessControl);
    }

    /**
     * A cycle is what a hand written traversal gets wrong in either direction.
     */
    public function testTheInverseLookupTerminatesOnACycle()
    {
        $hierarchy = [
            'ROLE_A' => ['ROLE_B'],
            'ROLE_B' => ['ROLE_A'],
        ];

        $security = new SecurityRoleHierarchy($hierarchy)
            ->getParentRoleNames(['ROLE_A']);
        $accessControl = new RoleHierarchy($hierarchy)
            ->getParentRoleNames(['ROLE_A']);

        sort($security);
        sort($accessControl);

        static::assertSame($security, $accessControl);
    }

    /**
     * The two contracts declare the same method and know nothing of each other, Security having to
     * keep working with no trace of this component installed. The adapter is what lets a single
     * hierarchy serve both stacks instead of two objects built from the same configuration, and it
     * carries an application's own implementation across just as well.
     */
    public function testSecuritysHierarchyIsReachedThroughTheAdapter()
    {
        $hierarchy = new SecurityRoleHierarchy([
            'ROLE_ADMIN' => ['ROLE_USER'],
        ]);

        static::assertNotInstanceOf(RoleHierarchyInterface::class, $hierarchy, 'Security is left untouched.');

        $adapter = new RoleHierarchyAdapter($hierarchy);

        static::assertSame($hierarchy->getReachableRoleNames(['ROLE_ADMIN']), $adapter->getReachableRoleNames(['ROLE_ADMIN']));
        $this->assertAccessGranted(
            new RoleVoter($adapter)
                ->vote(new AccessRequest(new FakeUser('alice', ['ROLE_ADMIN']), 'ROLE_USER')),
        );
    }
}
