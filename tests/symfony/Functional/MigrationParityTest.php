<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Twig\Error\SyntaxError;

/**
 * The three bricks an application asks its questions through, under the three shapes a migration
 * goes through: SecurityBundle alone, both bundles, this bundle alone.
 *
 * A requester holding ROLE_ADMIN reaches all three, one holding ROLE_USER is refused by all three,
 * and the answer is the same whichever shape the application has. The controller and the template
 * are never written twice: that they do not move is the whole point.
 *
 * The requester is authenticated in the three columns on purpose. A firewall sends an anonymous
 * visitor to its entry point where the component answers 403, a difference that is legitimate and
 * would hide everything else.
 */
class MigrationParityTest extends WebTestCase
{
    private static string $shape = MigrationParityKernel::SECURITY;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new MigrationParityKernel(self::$shape);
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideBricks(): iterable
    {
        yield 'a url rule, held' => ['/guarded-by-a-rule', 'alice', 200];
        yield 'a url rule, refused' => ['/guarded-by-a-rule', 'bob', 403];
        yield 'the attribute, held' => ['/guarded-by-the-attribute', 'alice', 200];
        yield 'the attribute, refused' => ['/guarded-by-the-attribute', 'bob', 403];
        yield 'a template, either way' => ['/template', 'alice', 200];
        yield 'the controller helper, held' => ['/helper/deny-unless', 'alice', 200];
        yield 'the controller helper, refused' => ['/helper/deny-unless', 'bob', 403];
    }

    #[DataProvider('provideBricks')]
    public function testTheThreeShapesAnswerAlike(string $path, string $user, int $expected)
    {
        $security = $this->statusOf(MigrationParityKernel::SECURITY, $path, $user);
        $both = $this->statusOf(MigrationParityKernel::BOTH, $path, $user);
        $alone = $this->statusOf(MigrationParityKernel::ACCESS_CONTROL, $path, $user);

        $this->assertSame($expected, $security, 'Security did not answer what this test assumes.');
        $this->assertSame($security, $both, 'Installing the bundle changed the answer.');
        $this->assertSame($security, $alone, 'The component alone does not answer like Security.');
    }

    /**
     * The helper of AbstractController is the one place where Symfony's own code branches on which
     * stack is there, asking Security first and this component only where there is no Security. A
     * divergence would be silent, the two branches each being right on their own.
     */
    #[DataProvider('provideRequesters')]
    public function testTheControllerHelperAnswersAlikeInTheThreeShapes(string $user, string $expected)
    {
        $security = $this->contentOf(MigrationParityKernel::SECURITY, '/helper/is-granted', $user);
        $both = $this->contentOf(MigrationParityKernel::BOTH, '/helper/is-granted', $user);
        $alone = $this->contentOf(MigrationParityKernel::ACCESS_CONTROL, '/helper/is-granted', $user);

        $this->assertSame($expected, $security, 'Security did not answer what this test assumes.');
        $this->assertSame($security, $both, 'Installing the bundle changed the answer.');
        $this->assertSame($security, $alone, 'The component alone does not answer like Security.');
    }

    /**
     * The template says the same thing in the three, which is what lets it move across untouched.
     */
    #[DataProvider('provideTemplateRequesters')]
    public function testTheTemplateReadsAlikeInTheThreeShapes(string $user, string $expected)
    {
        $security = $this->contentOf(MigrationParityKernel::SECURITY, '/template', $user);
        $both = $this->contentOf(MigrationParityKernel::BOTH, '/template', $user);
        $alone = $this->contentOf(MigrationParityKernel::ACCESS_CONTROL, '/template', $user);

        $this->assertSame($expected, $security, 'Security did not render what this test assumes.');
        $this->assertSame($security, $both, 'Installing the bundle changed the rendering.');
        $this->assertSame($security, $alone, 'The component alone does not render like Security.');
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideTemplateRequesters(): iterable
    {
        yield 'a requester who holds the role' => ['alice', 'admin|not-super'];
        yield 'a requester who does not' => ['bob', 'not-admin|not-super'];
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRequesters(): iterable
    {
        yield 'a requester who holds the role' => ['alice', 'granted'];
        yield 'a requester who does not' => ['bob', 'denied'];
    }

    /**
     * What a template loses on the way out, said here rather than discovered in production. The four
     * impersonation functions and access_decision() are Security's, kept by its own extension where
     * it is registered and simply absent where it is not.
     *
     * A missing Twig function raises, which is the one thing that must not change: an application
     * that drops SecurityBundle learns it at the first rendering, never by a silent denial.
     */
    public function testTheFunctionsThisComponentDoesNotAnswerAreSecuritysToKeep()
    {
        $this->assertSame(200, $this->request(MigrationParityKernel::SECURITY, '/security-only', 'alice', false)->getResponse()->getStatusCode());
        $this->assertSame(200, $this->request(MigrationParityKernel::BOTH, '/security-only', 'alice', false)->getResponse()->getStatusCode());

        $this->expectException(SyntaxError::class);
        $this->expectExceptionMessage('access_decision');

        $this->request(MigrationParityKernel::ACCESS_CONTROL, '/security-only', 'alice', false);
    }

    /**
     * access_decision() is delegated to Security, but what it hands back is filled by whoever holds
     * the decision manager, which is this component from the moment the bundle is registered.
     *
     * Measured before the fix: the verdict and the votes travelled, the algorithm did not. A
     * template printing access_decision(...).strategy said "affirmative" and started saying nothing
     * at all, which is a loss no error reports.
     *
     * The word is the one security.yaml used, not this component's name for the same algorithm: a
     * template that printed "affirmative" must not start printing "permit_overrides" either.
     */
    public function testTheDelegatedDecisionIsFilledInFull()
    {
        $security = $this->contentOf(MigrationParityKernel::SECURITY, '/security-only', 'alice');
        $both = $this->contentOf(MigrationParityKernel::BOTH, '/security-only', 'alice');

        $this->assertSame('granted|affirmative|1', $security, 'Security did not answer what this test assumes.');
        $this->assertSame($security, $both, 'Installing the bundle emptied part of the decision.');
    }

    /**
     * What a template gains in exchange, and the reason it is not called access_decision(): this one
     * answers in the three shapes, including the one that has no Security at all, where asking why
     * an access was refused was simply impossible.
     *
     * The two live side by side while both bundles are registered, which is what a migration needs:
     * a template moves from one to the other page by page rather than in a single commit.
     *
     * Security alone does not publish it and raises rather than answering something, which is
     * asserted on the status as well: a page merely containing the name would pass just as well.
     */
    public function testTheComponentAnswersWhyInEveryShape()
    {
        $security = $this->contentOf(MigrationParityKernel::SECURITY, '/component-decision', 'alice');
        $both = $this->contentOf(MigrationParityKernel::BOTH, '/component-decision', 'alice');
        $alone = $this->contentOf(MigrationParityKernel::ACCESS_CONTROL, '/component-decision', 'alice');

        $this->assertSame('denied|ACCESS_DENIED|voted', $both);
        $this->assertSame($both, $alone, 'The component alone does not answer like the two bundles together.');

        $this->assertSame(500, $this->request(MigrationParityKernel::SECURITY, '/component-decision', 'alice')->getResponse()->getStatusCode());
        $this->assertStringContainsString('access_control_decision', $security);
    }

    /**
     * @return iterable<string, array{0: string, 1: array<string, string>}>
     */
    /**
     * With both bundles the rules were declared under security.access_control and are enforced here,
     * as is the hierarchy, read through the adapter rather than built twice.
     */
    public static function provideIntegrations(): iterable
    {
        yield 'both bundles' => [MigrationParityKernel::BOTH, [
            'security_bundle' => '1',
            'rules' => 'security',
            'role_hierarchy' => 'security',
            'decisions' => 'component',
            'is_granted' => 'component',
            'twig' => 'component',
        ]];

        yield 'this bundle alone' => [MigrationParityKernel::ACCESS_CONTROL, [
            'security_bundle' => '',
            'rules' => 'component',
            'role_hierarchy' => 'component',
            'decisions' => 'component',
            'is_granted' => 'component',
            'twig' => 'component',
        ]];
    }

    /**
     * Which stack ends up answering each kind of question. Two applications carrying the same two
     * bundles can differ here, and they look alike from the outside until one of them answers
     * through an engine it did not choose, so the panel is where it has to be said.
     *
     * There is no third case: without this bundle registered there is no panel of ours at all.
     *
     * @param array<string, string> $expected
     */
    #[DataProvider('provideIntegrations')]
    public function testThePanelSaysWhichStackAnswersWhat(string $shape, array $expected)
    {
        self::$shape = $shape;
        self::ensureKernelShutdown();
        static::createClient();

        $collector = static::getContainer()->get('data_collector.access_control');
        $collector->lateCollect();

        $integration = [];
        foreach ($collector->getIntegration() as $key => $value) {
            $integration[$key] = trim((string) $value, '"');
        }

        foreach ($expected as $key => $value) {
            $this->assertSame($value, $integration[$key] ?? null, \sprintf('The panel says the wrong thing about "%s".', $key));
        }
    }

    private function statusOf(string $shape, string $path, string $user): int
    {
        return $this->request($shape, $path, $user)->getResponse()->getStatusCode();
    }

    private function contentOf(string $shape, string $path, string $user): string
    {
        return trim($this->request($shape, $path, $user)->getResponse()->getContent());
    }

    private function request(string $shape, string $path, string $user, bool $catchExceptions = true): KernelBrowser
    {
        self::$shape = $shape;
        self::ensureKernelShutdown();

        $client = static::createClient();
        $client->catchExceptions($catchExceptions);
        $client->request('GET', $path, server: [
            'PHP_AUTH_USER' => $user,
            'PHP_AUTH_PW' => 'pa$$word',
            'HTTP_X_ROLES' => 'alice' === $user ? 'ROLE_ADMIN' : 'ROLE_USER',
        ]);

        return $client;
    }
}
