<?php

declare(strict_types=1);

namespace AccessControl\Tests\Twig;

use AccessControl\AccessControlManager;
use AccessControl\AccessControlManagerInterface;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\RequesterBoundChecker;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PublishedPostVoter;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Twig\AccessControlExtension;
use AccessControl\Voter\RBAC\RoleVoter;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

final class AccessControlExtensionTest extends TestCase
{
    /**
     * The first two names are Security's, so a template moves across without being rewritten.
     *
     * The last two are this component's own, deliberately not access_decision(): that one hands
     * back an object of Security's whose shape differs, and a function whose return type depended
     * on which bundles are installed would be a trap. Both can be called from the same template
     * during a migration.
     */
    public function testTheFunctionNames()
    {
        $names = array_map(static fn ($function) => $function->getName(), $this->createExtension()->getFunctions());

        static::assertSame([
            'is_granted',
            'is_granted_for_user',
            'access_control_decision',
            'access_control_decision_for_user',
        ], $names);
    }

    public function testARoleTheRequesterHolds()
    {
        static::assertTrue($this->createExtension()->isGranted('ROLE_ADMIN'));
    }

    public function testARoleTheRequesterDoesNotHold()
    {
        static::assertFalse($this->createExtension()->isGranted('ROLE_SUPER_ADMIN'));
    }

    /**
     * A requester nobody provided holds nothing, which fails closed rather than raising.
     */
    public function testNoRequesterAtAllIsNotAnError()
    {
        static::assertFalse($this->createExtension(null)->isGranted('ROLE_ADMIN'));
    }

    public function testTheSubjectReachesTheVoter()
    {
        $extension = $this->createExtension();

        static::assertTrue($extension->isGranted('read', new Post(published: true)));
        static::assertFalse($extension->isGranted('read', new Post(published: false)));
    }

    /**
     * Deciding for someone other than the current requester is native here: the access request names
     * its own requester, where Security needs a dedicated contract on the checker.
     */
    public function testDecidingForAnotherRequester()
    {
        $extension = $this->createExtension(new StandaloneRequester(['ROLE_USER']));

        static::assertFalse($extension->isGranted('ROLE_ADMIN'));
        static::assertTrue($extension->isGrantedForUser(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));
    }

    public function testTheFunctionsAnswerFromATemplate()
    {
        $twig = new Environment(new ArrayLoader([
            'page' => '{{ is_granted("ROLE_ADMIN") ? "yes" : "no" }}/{{ is_granted("ROLE_SUPER_ADMIN") ? "yes" : "no" }}',
        ]));
        $twig->addExtension($this->createExtension());

        static::assertSame('yes/no', $twig->render('page'));
    }

    /**
     * Security accepts a field and hands it to symfony/acl, whose FieldVote no voter here
     * understands. Answering false would be a denial the template cannot tell from a real one.
     */
    public function testAFieldIsRefusedRatherThanQuietlyDenied()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('field level access control');

        $this->createExtension()
            ->isGranted('ROLE_ADMIN', null, 'title');
    }

    public function testAFieldIsRefusedForAnotherRequesterToo()
    {
        $this->expectException(LogicException::class);

        $this->createExtension()
            ->isGrantedForUser(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN', null, 'title');
    }

    /**
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideAttributes(): iterable
    {
        yield 'a role the requester holds' => ['ROLE_ADMIN', true];
        yield 'a role the requester does not' => ['ROLE_SUPER_ADMIN', false];
        yield 'an attribute nobody answers' => ['NOBODY_ANSWERS_THIS', false];
    }

    /**
     * Two functions of the same extension answering the same question must not answer it twice: the
     * verdict is read off the decision rather than computed again beside it. This is the divergence
     * that was measured on is_granted_for_user() and is not to be recreated.
     */
    #[DataProvider('provideAttributes')]
    public function testTheVerdictAndTheDecisionAgree(string $attribute, bool $expected)
    {
        $extension = $this->createExtension();

        static::assertSame($expected, $extension->isGranted($attribute));
        static::assertSame($expected, $extension->decision($attribute)->isGranted());

        $other = new StandaloneRequester(['ROLE_ADMIN']);
        static::assertSame($extension->isGrantedForUser($other, $attribute), $extension->decisionForUser($other, $attribute)->isGranted());
    }

    /**
     * What the decision is asked for in the first place: a template that says why, which the bare
     * verdict of is_granted() cannot.
     */
    public function testTheDecisionCarriesTheReasonToATemplate()
    {
        $twig = new Environment(new ArrayLoader([
            'page' => '{% set d = access_control_decision("ROLE_SUPER_ADMIN") %}{{ d.isGranted ? "yes" : "no" }}/{{ d.decision.value }}/{{ d.votes|length > 0 ? "voted" : "silent" }}',
        ]));
        $twig->addExtension($this->createExtension());

        static::assertSame('no/ACCESS_DENIED/voted', $twig->render('page'));
    }

    /**
     * An authentication state is refused for a requester other than the current one, exactly as
     * is_granted_for_user() refuses it, rather than being answered by a different path.
     */
    public function testAnAuthenticationStateIsRefusedForAnotherRequesterHereToo()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('IS_AUTHENTICATED_FULLY');

        $this->createExtension()
            ->decisionForUser(new StandaloneRequester(['ROLE_ADMIN']), 'IS_AUTHENTICATED_FULLY');
    }

    private function createExtension(mixed $requester = new StandaloneRequester(['ROLE_ADMIN'])): AccessControlExtension
    {
        $manager = $this->createManager();

        return new AccessControlExtension(
            new RequesterBoundChecker($manager, new StaticRequesterProvider($requester)),
            $manager,
        );
    }

    private function createManager(): AccessControlManagerInterface
    {
        return new AccessControlManager([new PermitOverridesStrategy()], [new RoleVoter(), new PublishedPostVoter()]);
    }
}
