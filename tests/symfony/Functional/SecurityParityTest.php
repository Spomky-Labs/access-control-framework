<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestWith;
use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use AccessControl\Bridge\Security\RoleHierarchyAdapter;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The same application with and without this bundle registered.
 *
 * Registering it points security.access.decision_manager at the component, so #[IsGranted] stops
 * being answered by Security and starts being answered by AccessControl without a line changing in
 * security.yaml. Comparing the two applications is therefore the migration itself, and the only
 * honest way to compare: inside the switched application both attributes run on the same engine, so
 * nothing there could prove a parity.
 */
class SecurityParityTest extends WebTestCase
{
    use AccessControlAssertionsTrait;

    private static bool $switched = true;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecurityParityKernel(self::$switched);
    }

    public static function provideQuestions(): iterable
    {
        yield 'a role the user holds' => ['held-role', 'bob', 200];
        yield 'a role reached through the hierarchy' => ['held-role', 'alice', 200];
        yield 'a role out of reach' => ['unreachable-role', 'alice', 403];
        yield 'an authentication state' => ['authenticated', 'bob', 200];
        yield 'public access' => ['public', 'bob', 200];
        yield 'an application voter, allowed' => ['application-voter', 'alice', 200];
        yield 'an application voter, refused' => ['application-voter', 'bob', 403];
    }

    /**
     * The heart of it: an untouched #[IsGranted] controller answers the same before and after the
     * switch, the second time through the component.
     */
    #[DataProvider('provideQuestions')]
    public function testAnIsGrantedControllerAnswersAlikeBeforeAndAfterTheSwitch(string $route, string $user, int $expected)
    {
        $before = $this->statusOf(false, '/security/'.$route, $user);
        $after = $this->statusOf(true, '/security/'.$route, $user);

        $this->assertSame($expected, $before, \sprintf('Security answered %d on "%s".', $before, $route));
        $this->assertSame($before, $after, \sprintf('The switch changed the answer on "%s" for "%s".', $route, $user));
    }

    /**
     * And within the switched application, the two ways of writing the requirement agree. Both run
     * on the component here, so this is about the two attributes and their listeners, not about
     * the two stacks.
     */
    #[DataProvider('provideQuestions')]
    public function testTheTwoAttributesAgreeOnceSwitched(string $route, string $user, int $expected)
    {
        $isGranted = $this->statusOf(true, '/security/'.$route, $user);
        $accessPolicy = $this->statusOf(true, '/access-control/'.$route, $user);

        $this->assertSame($expected, $isGranted);
        $this->assertSame($isGranted, $accessPolicy, \sprintf('The two attributes disagree on "%s" for "%s".', $route, $user));
    }

    /**
     * The cases are grouped by what they exercise. First what reaches the decision manager, so what
     * the switch actually changes: single roles, then "roles: [ROLE_ADMIN, ROLE_MANAGER]" where
     * either one is enough and both branches are walked, since testing only the first would let a
     * broken second go unnoticed, then allow_if, which travels as an Expression among the
     * attributes. Last the matching side, which never reaches the decision manager and must come
     * out untouched.
     */
    public static function provideFirewallRules(): iterable
    {
        yield 'an admin path, held' => ['/dashboard/admin', 'alice', 200];
        yield 'an admin path, refused' => ['/dashboard/admin', 'bob', 403];
        yield 'a path on an inherited role' => ['/dashboard', 'alice', 200];
        yield 'a path on a directly held role' => ['/dashboard', 'bob', 200];
        yield 'a public path' => ['/anonymous', 'bob', 200];

        yield 'two roles, the first held' => ['/either', 'alice', 200];
        yield 'two roles, the second held' => ['/either', 'carol', 200];
        yield 'two roles, neither held' => ['/either', 'bob', 403];

        yield 'an expression that holds' => ['/allow-if', 'alice', 200];
        yield 'an expression that does not' => ['/allow-if', 'bob', 403];

        yield 'an ip rule that does not match' => ['/by-ip', 'bob', 200];
        yield 'a host rule that does not match' => ['/by-host', 'bob', 200];
        yield 'a method rule that does not match' => ['/by-method', 'bob', 200];
    }

    public static function provideMatchingRules(): iterable
    {
        yield 'a method rule that matches' => ['POST', '/by-method', [], 403];
        yield 'an ip rule that matches' => ['GET', '/by-ip', ['REMOTE_ADDR' => '10.0.0.1'], 403];
        yield 'a host rule that matches' => ['GET', '/by-host', ['HTTP_HOST' => 'forbidden.example.com'], 403];
        yield 'a channel rule that matches' => ['GET', '/secure-channel', [], 301];
    }

    /**
     * The matching side of a rule: method, ip, host, channel. None of it goes through the decision
     * manager, so the switch has to leave it strictly alone.
     */
    #[DataProvider('provideMatchingRules')]
    public function testTheMatchingSideOfARuleIsUntouchedByTheSwitch(string $method, string $path, array $server, int $expected)
    {
        $before = $this->statusOf(false, $path, 'bob', $method, $server);
        $after = $this->statusOf(true, $path, 'bob', $method, $server);

        $this->assertSame($expected, $before, \sprintf('Security answered %d on "%s".', $before, $path));
        $this->assertSame($before, $after, \sprintf('The switch changed the answer on "%s".', $path));
    }

    /**
     * The most used feature of the lot, and the one no attribute is involved in: the controllers
     * behind these paths carry nothing at all, security.access_control alone guards them. Once the
     * flag is on, it is the component that answers, and the security.yaml has not moved.
     */
    #[DataProvider('provideFirewallRules')]
    public function testTheFirewallRulesAnswerAlikeBeforeAndAfterTheSwitch(string $path, string $user, int $expected)
    {
        $before = $this->statusOf(false, $path, $user);
        $after = $this->statusOf(true, $path, $user);

        $this->assertSame($expected, $before, \sprintf('Security answered %d on "%s".', $before, $path));
        $this->assertSame($before, $after, \sprintf('The switch changed the answer on "%s" for "%s".', $path, $user));
    }

    /**
     * A firewall rule may name several roles, which Security satisfies with any one of them. That
     * is the multi attribute call the adapter had to reproduce.
     */
    public function testTheDenialOfAFirewallRuleIsRecorded()
    {
        $client = $this->clientFor(true);
        $client->request('GET', '/dashboard/admin', [], [], $this->credentials('bob'));

        $this->assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertAccessWasDeniedOn('ROLE_ADMIN');
    }

    /**
     * The two parts of a rule that actually reach the decision manager, seen from our own log so
     * that "the answer is the same" cannot be confused with "the component was consulted".
     */
    public function testTheRolesAndTheExpressionAreDecidedByTheComponent()
    {
        $client = $this->clientFor(true);

        $client->request('GET', '/either', [], [], $this->credentials('bob'));
        $this->assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertAccessWasDeniedOn('ROLE_ADMIN');
        $this->assertAccessWasDeniedOn('ROLE_MANAGER');

        $client->request('GET', '/allow-if', [], [], $this->credentials('bob'));
        $this->assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertNotEmpty(self::getAccessDecisionEvents()->getDecisions());
    }

    private function statusOf(bool $switched, string $path, string $user, string $method = 'GET', array $server = []): int
    {
        $client = $this->clientFor($switched);
        $client->request($method, $path, [], [], $server + $this->credentials($user));

        return $client->getResponse()->getStatusCode();
    }

    /**
     * Two applications in one test, so the previous kernel has to go before the next boots.
     */
    private function clientFor(bool $switched): KernelBrowser
    {
        static::ensureKernelShutdown();
        self::$switched = $switched;

        return static::createClient();
    }

    /**
     * Proves the compiler pass really handed the role hierarchy to the AccessControl role voter:
     * alice holds ROLE_ADMIN only, and reaches ROLE_USER through security.role_hierarchy.
     */
    public function testTheRoleHierarchyReachesTheAccessControlVoter()
    {
        $client = $this->clientFor(true);
        $client->request('GET', '/access-control/held-role', [], [], $this->credentials('alice'));

        $this->assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertAccessWasGrantedOn('ROLE_USER');
    }

    /**
     * The component reports denials with its own exception, and this is what proves the firewall
     * still handles them: an anonymous visitor is sent to the entry point, a 401 challenge here,
     * rather than answered 403. Only the firewall's exception listener does that, and it only sees
     * the denial because the bridge listener says it again in Security's own terms first.
     *
     * Both attributes are asked, since a divergence here would be a migration trap.
     */
    #[TestWith(['/security/held-role'])]
    #[TestWith(['/access-control/held-role'])]
    public function testAnAnonymousDenialIsSentToTheFirewallEntryPoint(string $path)
    {
        $client = $this->clientFor(true);
        $client->request('GET', $path);

        $this->assertSame(401, $client->getResponse()->getStatusCode());
        $this->assertSame('Basic realm="Secured Area"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /**
     * And that it reaches it through Security's very own service, wrapped in the adapter that makes
     * it answer this component's contract: an application declares its hierarchy once, in
     * security.yaml, and one tree answers both stacks.
     */
    public function testTheTwoStacksShareOneRoleHierarchy()
    {
        $client = $this->clientFor(true);
        $container = $client->getContainer()->get('test.service_container');

        $this->assertInstanceOf(RoleHierarchyAdapter::class, $container->get('access_control.role_hierarchy'));
        $this->assertSame(
            $container->get('security.role_hierarchy')->getReachableRoleNames(['ROLE_ADMIN']),
            $container->get('access_control.role_hierarchy')->getReachableRoleNames(['ROLE_ADMIN']),
        );
        $this->assertSame(['ROLE_ADMIN', 'ROLE_USER'], $container->get('access_control.role_hierarchy')->getReachableRoleNames(['ROLE_ADMIN']));
    }

    /**
     * And that the diagnostic the response withholds is available to the test.
     */
    public function testTheDenialNamesItsVoter()
    {
        $client = $this->clientFor(true);
        $client->request('GET', '/access-control/unreachable-role', [], [], $this->credentials('alice'));

        $this->assertSame(403, $client->getResponse()->getStatusCode());
        $this->assertAccessWasDeniedOn('ROLE_SUPER_ADMIN');
        $this->assertAccessWasDeniedBy(RoleVoter::class);
    }

    private function credentials(string $user): array
    {
        return ['PHP_AUTH_USER' => $user, 'PHP_AUTH_PW' => 'pa$$word'];
    }
}
