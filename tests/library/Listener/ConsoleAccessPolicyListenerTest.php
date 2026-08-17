<?php

declare(strict_types=1);

namespace AccessControl\Tests\Listener;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\ExpressionLanguage;
use AccessControl\Handler\AccessPolicyHandler;
use AccessControl\Handler\AllHandler;
use AccessControl\Handler\AtLeastOneOfHandler;
use AccessControl\Handler\WhenHandler;
use AccessControl\Listener\ConsoleAccessPolicyListener;
use AccessControl\Requester\RequesterProviderInterface;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\ClassLevelPolicyCommand;
use AccessControl\Tests\Fixtures\ConditionalPolicyCommand;
use AccessControl\Tests\Fixtures\ExecuteLevelPolicyCommand;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\InvokablePolicyCommand;
use AccessControl\Tests\Fixtures\PlainCommand;
use AccessControl\Tests\Fixtures\SubjectRecordingVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\LazyCommand;
use Symfony\Component\Console\Command\TraceableCommand;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\Console\Event\ConsoleCommandEvent as CommandEvent;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Stopwatch\Stopwatch;

final class ConsoleAccessPolicyListenerTest extends TestCase
{
    private SubjectRecordingVoter $subjectVoter;

    public function testClassLevelPolicyIsGranted(): void
    {
        $this->createListener()->onConsoleCommand($this->createEvent(new ClassLevelPolicyCommand()));

        $this->expectNotToPerformAssertions();
    }

    public function testClassLevelPolicyIsDenied(): void
    {
        $listener = $this->createListener(new StaticRequesterProvider(new FakeToken(new FakeUser(roles: ['ROLE_USER']))));

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access Denied.');

        $listener->onConsoleCommand($this->createEvent(new ClassLevelPolicyCommand()));
    }

    public function testPolicyOnInvokeIsRead(): void
    {
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Nope.');

        $this->createListener()->onConsoleCommand($this->createEvent(new InvokablePolicyCommand()));
    }

    /**
     * The code of the exception is what Application::run() reports as the exit status, so it is a
     * contract with the scripts calling the command and the number itself is pinned. Asserting the
     * constant alone would compare it to itself and hold just as well if its value moved.
     *
     * 113 is what the console already means by "this command was not allowed to run", and it is
     * preferred to an HTTP status because a 403 would come out as 255, the status being capped.
     */
    public function testDenialUsesAConsoleExitCodeAndNotAnHttpStatus(): void
    {
        try {
            $this->createListener()->onConsoleCommand($this->createEvent(new InvokablePolicyCommand()));
            $this->fail('An AccessDeniedException should have been thrown.');
        } catch (AccessDeniedException $exception) {
            $this->assertSame(113, $exception->getCode());
            $this->assertSame(CommandEvent::RETURN_CODE_DISABLED, $exception->getCode());
            $this->assertLessThanOrEqual(255, $exception->getCode());
        }
    }

    public function testPolicyOnExecuteIsReadAndArgumentsAreResolved(): void
    {
        $command = new ExecuteLevelPolicyCommand();
        $command->setDefinition(new InputDefinition([new InputArgument('slug', InputArgument::REQUIRED)]));

        $this->createListener()->onConsoleCommand($this->createEvent($command, ['slug' => 'hello-world']));

        $this->assertSame(['hello-world'], $this->subjectVoter->subjects);
    }

    public function testCommandWithoutPolicyIsIgnored(): void
    {
        $this->createListener()->onConsoleCommand($this->createEvent(new PlainCommand()));

        $this->expectNotToPerformAssertions();
    }

    public function testEventWithoutCommandIsIgnored(): void
    {
        $event = new ConsoleCommandEvent(null, new ArrayInput([]), new NullOutput());

        $this->createListener()->onConsoleCommand($event);

        $this->expectNotToPerformAssertions();
    }

    /**
     * The condition of a When composite speaks about whatever the entry point handed over, so the
     * very same composite that reads an HTTP method on the web reads a console option here. This
     * is what a methods parameter on the policy itself could never have done.
     */
    public function testAConditionReadsTheContextOfTheEntryPoint(): void
    {
        $command = new ConditionalPolicyCommand();

        $this->createListener()->onConsoleCommand($this->createEvent($command));

        $this->expectException(AccessDeniedException::class);

        $this->createListener()->onConsoleCommand($this->createEvent($command, ['--force' => true]));
    }

    /**
     * The console does not always hand over the command itself. It wraps a lazily registered one,
     * and it wraps every command at all once tracing is on, which is what --profile turns on. A
     * wrapper carries none of the attributes, so reflecting it would find no policy and let a
     * guarded command run unguarded.
     */
    public function testAPolicyIsFoundThroughATracingWrapper(): void
    {
        $command = new TraceableCommand(new ClassLevelPolicyCommand(), new Stopwatch());
        $listener = $this->createListener(new StaticRequesterProvider(new FakeToken(new FakeUser(roles: ['ROLE_USER']))));

        $this->expectException(AccessDeniedException::class);

        $listener->onConsoleCommand($this->createEvent($command));
    }

    public function testAPolicyIsFoundThroughALazyWrapper(): void
    {
        $command = new LazyCommand('class-level', [], '', false, static fn (): Command => new ClassLevelPolicyCommand());
        $listener = $this->createListener(new StaticRequesterProvider(new FakeToken(new FakeUser(roles: ['ROLE_USER']))));

        $this->expectException(AccessDeniedException::class);

        $listener->onConsoleCommand($this->createEvent($command));
    }

    private function createEvent(Command $command, array $parameters = []): ConsoleCommandEvent
    {
        $input = new ArrayInput($parameters, $command->getDefinition());

        return new ConsoleCommandEvent($command, $input, new NullOutput());
    }

    private function createListener(?RequesterProviderInterface $requesterProvider = null): ConsoleAccessPolicyListener
    {
        $this->subjectVoter = new SubjectRecordingVoter('read');

        $manager = new AccessControlManager(
            [new PermitOverridesStrategy()],
            [new RoleVoter(), $this->subjectVoter],
        );

        $evaluator = new AccessPolicyEvaluator([
            new AccessPolicyHandler($manager),
            new AllHandler(),
            new AtLeastOneOfHandler(),
            new WhenHandler(new ExpressionLanguage()),
        ]);

        $requesterProvider ??= new StaticRequesterProvider(new FakeToken(new FakeUser(roles: ['ROLE_ADMIN', 'ROLE_USER'])));

        return new ConsoleAccessPolicyListener($requesterProvider, $evaluator);
    }
}
