<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The console entry point, in an application that has no Security at all.
 *
 * CommandTester runs the command itself and never dispatches ConsoleEvents::COMMAND, so a guarded
 * command looks allowed under it. The console has to be entered through an Application carrying
 * the dispatcher, which is what ApplicationTester does.
 */
final class AccessControlConsoleTest extends KernelTestCase
{
    use AccessControlAssertionsTrait;

    private static bool $withExitCodeListener = false;

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new AccessControlKernel(self::$withExitCodeListener);
    }

    /**
     * The When composite reads the console input the same way it reads the HTTP request on the
     * web, which is what a methods parameter on the policy could never have done.
     */
    public function testAGuardedCommandRunsWhenItsConditionDoesNotHold()
    {
        $tester = $this->consoleTester();
        $tester->run([
            'command' => 'app:access-controlled',
        ]);

        $tester->assertCommandIsSuccessful();
        $this->assertAccessDecisionCount(0);
    }

    public function testAGuardedCommandIsStoppedWhenAccessIsDenied()
    {
        $tester = $this->consoleTester();
        $tester->run([
            'command' => 'app:access-controlled',
            '--destructive' => true,
        ]);

        static::assertSame(ConsoleCommandEvent::RETURN_CODE_DISABLED, $tester->getStatusCode());
        $this->assertAccessWasDeniedOn('DELETE');
        $this->assertAccessWasDeniedBy(PermissionVoter::class);
    }

    /**
     * The exit status of a denial, end to end and as the number itself. This is what scripts
     * calling the command read, so it is pinned rather than compared to the constant it is written
     * with, which would hold just as well if that constant's value moved.
     *
     * 113 is what the console already means by "this command was not allowed to run". An HTTP
     * status is not usable here: a 403 would come out as 255, the exit status being capped at it.
     */
    public function testTheDefaultExitStatusOfADenial()
    {
        $tester = $this->consoleTester();
        $tester->run([
            'command' => 'app:access-controlled',
            '--destructive' => true,
        ]);

        static::assertSame(113, $tester->getStatusCode());
        static::assertSame(113, ConsoleCommandEvent::RETURN_CODE_DISABLED, 'The exit status is meant to be the one the console already has a name for.');
    }

    /**
     * A command that was allowed keeps its own exit status, the guard adding nothing to it.
     */
    public function testAnAllowedCommandKeepsItsOwnExitStatus()
    {
        $tester = $this->consoleTester();
        $tester->run([
            'command' => 'app:access-controlled',
        ]);

        static::assertSame(0, $tester->getStatusCode());
        static::assertStringContainsString('done', $tester->getDisplay());
    }

    /**
     * Why the denial travels as an exception rather than by disabling the command: disableCommand()
     * returns the same 113 but prints nothing and dispatches no error event, so the user would be
     * refused without being told why and the application would have no hold on the refusal.
     *
     * The message asserted here is the one carried by the When rather than by the policy it wraps,
     * which is how a refusal that only exists at this entry point gets words of its own.
     */
    public function testTheReasonOfADenialReachesTheTerminal()
    {
        $tester = $this->consoleTester();
        $tester->run([
            'command' => 'app:access-controlled',
            '--destructive' => true,
        ]);

        static::assertStringContainsString(AccessControlledCommand::DENIAL, $tester->getDisplay());
        static::assertStringNotContainsString('done', $tester->getDisplay());
    }

    /**
     * The same command, profiled. Symfony then hands the listener a TraceableCommand rather than the
     * command itself, and a wrapper carries none of the attributes: the guard used to be skipped
     * outright, so a command that must be refused ran instead. Failing open under a debug flag is
     * the one failure an access control component cannot have.
     */
    public function testAGuardedCommandIsStoppedUnderProfileToo()
    {
        $tester = $this->consoleTester();
        $tester->run([
            'command' => 'app:access-controlled',
            '--destructive' => true,
            '--profile' => true,
        ]);

        static::assertSame(ConsoleCommandEvent::RETURN_CODE_DISABLED, $tester->getStatusCode());
        $this->assertAccessWasDeniedOn('DELETE');
    }

    public function testAProfiledCommandStillRunsWhenAllowed()
    {
        $tester = $this->consoleTester();
        $tester->run([
            'command' => 'app:access-controlled',
            '--profile' => true,
        ]);

        $tester->assertCommandIsSuccessful();
        $this->assertAccessDecisionCount(0);
    }

    /**
     * The component fixes no exit code of its own beyond the one the console already means by it,
     * because an exit code is read by scripts an application owns and not by the policy that was
     * refused. What it owes is a way out, and the console has one: setExitCode() on the error event
     * has the last word over the exception.
     *
     * This is pinned rather than documented alone because the way out disappears the day the
     * denial stops travelling as an exception, disableCommand() dispatching no error event at all.
     */
    public function testAnApplicationDecidesItsOwnExitCode()
    {
        $tester = $this->consoleTester(withExitCodeListener: true);
        $tester->run([
            'command' => 'app:access-controlled',
            '--destructive' => true,
        ]);

        static::assertSame(ConsoleExitCodeListener::EXIT_CODE, $tester->getStatusCode());
        $this->assertAccessWasDeniedOn('DELETE');
    }

    private function consoleTester(bool $withExitCodeListener = false): ApplicationTester
    {
        self::$withExitCodeListener = $withExitCodeListener;
        static::ensureKernelShutdown();
        static::bootKernel();

        $application = new Application(static::$kernel);
        $application->setAutoExit(false);

        return new ApplicationTester($application);
    }
}
