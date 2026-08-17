<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use AccessControl\Bridge\Workflow\GuardListener;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Workflow\EventListener\GuardListener as WorkflowGuardListener;

/**
 * A guarded workflow transition, under the three shapes an application can have.
 *
 * The third one did not compile before this: Workflow's guard listener is typed on four contracts of
 * Security and its own compiler pass refuses to build without their services. Two of those contracts
 * belong to the authorization half and are due to move to this component, so the replacement is
 * written now and measured against the original, rather than improvised the day Security loses them.
 */
class WorkflowGuardTest extends TestCase
{
    /**
     * is_valid() is the one guard function that has nothing to do with access: Workflow adds it to
     * the language it borrows from Security, and an application already using it must keep it.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: bool}>
     */
    public static function provideGuards(): iterable
    {
        yield 'a granting voter' => ["is_granted('EDIT', subject)", 'A title', true];
        yield 'a denying voter' => ["is_granted('DELETE', subject)", 'A title', false];
        yield 'an attribute nobody answers' => ["is_granted('NOBODY_ANSWERS_THIS', subject)", 'A title', false];
        yield 'a plain expression on the subject' => ['subject.title matches "/^A/"', 'A title', true];

        yield 'is_valid on a valid subject' => ['is_valid(subject)', 'A title', true];
        yield 'is_valid on an invalid subject' => ['is_valid(subject)', null, false];
    }

    /**
     * Security alone has none of the fixture voters, so it only agrees where the expression does not
     * ask the decision manager anything.
     */
    #[DataProvider('provideGuards')]
    public function testTheThreeShapesGuardAlike(string $guard, ?string $title, bool $expected)
    {
        $security = $this->canPublish(WorkflowGuardKernel::SECURITY, $guard, $title);
        $both = $this->canPublish(WorkflowGuardKernel::BOTH, $guard, $title);
        $alone = $this->canPublish(WorkflowGuardKernel::ACCESS_CONTROL, $guard, $title);

        $this->assertSame($expected, $both, 'Installing the bundle did not answer what this test assumes.');
        $this->assertSame($both, $alone, 'The component alone does not guard like the two bundles together.');

        if (!str_contains($guard, 'is_granted')) {
            $this->assertSame($both, $security, 'Security alone does not guard alike either.');
        }
    }

    /**
     * The guards of a workflow all reach the same listener, so each one has to be matched against
     * the transition it was written for. Publishing is guarded by an expression that holds, and
     * discarding by one that never does.
     */
    public function testAGuardOnlyBlocksItsOwnTransition()
    {
        $kernel = $this->boot(WorkflowGuardKernel::ACCESS_CONTROL, "is_granted('EDIT', subject)");
        $workflow = $kernel->getContainer()->get('test.workflow.article');

        $this->assertTrue($workflow->can($this->article(), 'publish'));
        $this->assertFalse($workflow->can($this->article(), 'discard'));
    }

    /**
     * The takeover is conditional, unlike the rest of the bridge. An application that has Security
     * already reaches this component through the decision manager, so replacing the listener would
     * buy nothing and would cost the trust resolver an expression may name.
     *
     * @return iterable<string, array{0: string, 1: class-string}>
     */
    public static function provideExpectedListeners(): iterable
    {
        yield 'Security alone keeps its own listener' => [WorkflowGuardKernel::SECURITY, WorkflowGuardListener::class];
        yield 'both bundles keep it too' => [WorkflowGuardKernel::BOTH, WorkflowGuardListener::class];
        yield 'this bundle alone is the only swap' => [WorkflowGuardKernel::ACCESS_CONTROL, GuardListener::class];
    }

    #[DataProvider('provideExpectedListeners')]
    public function testWhichListenerEachShapeCompiles(string $shape, string $expected)
    {
        $this->assertSame($expected, $this->guardListenerClassOf($shape));
    }

    /**
     * The check in FrameworkExtension was widened to accept this component in place of Security, and
     * that must not have opened a hole: a guard with neither Security nor this bundle to apply it
     * still refuses to compile, rather than compiling into a transition nobody guards.
     */
    public function testAGuardWithNobodyToApplyItStillRefusesToCompile()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The "security.token_storage" service is needed to be able to use the workflow guard listener.');

        (new UnguardedWorkflowKernel())->boot();
    }

    private function canPublish(string $shape, string $guard, ?string $title): bool
    {
        $workflow = $this->boot($shape, $guard)->getContainer()->get('test.workflow.article');

        return $workflow->can($this->article($title), 'publish');
    }

    private function article(?string $title = 'A title'): Article
    {
        $article = new Article();
        $article->marking = 'draft';
        $article->title = $title;

        return $article;
    }

    private function boot(string $shape, string $guard): WorkflowGuardKernel
    {
        $kernel = new WorkflowGuardKernel($shape, $guard);
        $kernel->boot();

        return $kernel;
    }

    private function guardListenerClassOf(string $shape): ?string
    {
        $kernel = new class($shape) extends WorkflowGuardKernel {
            public ?string $guardListenerClass = null;

            protected function build(ContainerBuilder $container): void
            {
                parent::build($container);

                $container->addCompilerPass(new class($this) implements CompilerPassInterface {
                    public function __construct(private readonly Kernel $kernel)
                    {
                    }

                    public function process(ContainerBuilder $container): void
                    {
                        foreach ($container->getDefinitions() as $id => $definition) {
                            if (str_ends_with($id, '.listener.guard')) {
                                $this->kernel->guardListenerClass = $definition->getClass();
                            }
                        }
                    }
                }, PassConfig::TYPE_BEFORE_REMOVING);
            }
        };

        $kernel->boot();

        return $kernel->guardListenerClass;
    }
}
