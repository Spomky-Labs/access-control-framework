<?php

declare(strict_types=1);

namespace AccessControl\Listener;

use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\DecisionVote;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Requester\RequesterProviderInterface;
use ReflectionAttribute;
use ReflectionClass;
use ReflectionFunction;
use ReflectionMethod;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\LazyCommand;
use Symfony\Component\Console\Command\TraceableCommand;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Applies the access policies a command declares, before it is allowed to run.
 *
 * A denial leaves as an exception rather than by disabling the command, so that its reason reaches
 * the terminal and ConsoleEvents::ERROR is dispatched at all. The exception carries
 * RETURN_CODE_DISABLED, which is what the console already means by "this command was not allowed to
 * run", and which Application::run() turns into the exit status. An HTTP status has no place here:
 * a 403 would come out as 255, the exit status being capped.
 *
 * That value is deliberately not configurable. An exit status is read by scripts the application
 * owns rather than by the policy that was refused, and the console already offers the way out: a
 * listener on ConsoleEvents::ERROR calling setExitCode(), which writes the value onto the exception
 * as well and so has the last word. It can branch on the command or on the requester, which no
 * setting of ours would have allowed.
 *
 * @experimental
 */
final readonly class ConsoleAccessPolicyListener implements EventSubscriberInterface
{
    public function __construct(
        private RequesterProviderInterface $requesterProvider,
        private AccessPolicyEvaluator $accessPolicyEvaluator,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            ConsoleEvents::COMMAND => ['onConsoleCommand', 20],
        ];
    }

    public function onConsoleCommand(ConsoleCommandEvent $event): void
    {
        if (null === $command = $event->getCommand()) {
            return;
        }

        $input = $event->getInput();
        $context = new AccessPolicyContext(
            $this->requesterProvider->getRequester(),
            [...$input->getArguments(), ...$input->getOptions()],
            [
                'command' => $command,
                'input' => $input,
                'output' => $event->getOutput(),
            ],
            $command->getName() ?? $command::class,
        );

        foreach ($this->getAccessPolicies($command) as $accessPolicy) {
            if ($this->accessPolicyEvaluator->evaluate($accessPolicy, $context)->decision !== DecisionVote::ACCESS_DENIED) {
                continue;
            }

            self::recordTheInputOnTheTracingWrapper($command, $event);

            throw new AccessDeniedException($accessPolicy->message ?? 'Access Denied.', ConsoleCommandEvent::RETURN_CODE_DISABLED);
        }
    }

    /**
     * A refused command never runs, and a TraceableCommand records its input only when it does. The
     * profile is collected on terminate all the same, and reading an uninitialized typed property is
     * a fatal error, so refusing under --profile would crash instead of reporting the refusal.
     *
     * Filling the wrapper here is what the console would have done a moment later. The alternative,
     * declaring those properties with a default, belongs to symfony/console and is proposed there;
     * this stays correct either way, an already recorded input never being overwritten.
     */
    private static function recordTheInputOnTheTracingWrapper(Command $command, ConsoleCommandEvent $event): void
    {
        while ($command instanceof LazyCommand) {
            $command = $command->getCommand();
        }

        if (! $command instanceof TraceableCommand) {
            return;
        }

        $input = $event->getInput();

        $command->input ??= $input;
        $command->output ??= $event->getOutput();
        $command->arguments ??= $input->getArguments();
        $command->options ??= $input->getOptions();
        $command->ignoreValidation ??= false;
    }

    /**
     * The console hands over a wrapper rather than the command itself in two cases: a lazily
     * registered command, and any command at all once it is being traced, which is what --profile
     * turns on. A wrapper carries none of the attributes, so reflecting it would find no policy and
     * let a guarded command run unguarded. Failing open is the one thing this must never do.
     */
    private static function unwrap(Command $command): Command
    {
        while (true) {
            if ($command instanceof LazyCommand) {
                $command = $command->getCommand();

                continue;
            }

            if ($command instanceof TraceableCommand) {
                $command = $command->command;

                continue;
            }

            return $command;
        }
    }

    /**
     * @return iterable<AccessPolicyInterface>
     */
    private function getAccessPolicies(Command $command): iterable
    {
        $command = self::unwrap($command);

        $classes = [
            $command::class => new ReflectionClass($command),
        ];
        $functions = [];

        if (null !== $code = $command->getCode()) {
            $functions[] = $function = new ReflectionFunction($code(...));

            if (null !== $scope = $function->getClosureScopeClass()) {
                $classes[$scope->name] ??= $scope;
            }
        } else {
            $functions[] = new ReflectionMethod($command, 'execute');
        }

        foreach ([...array_values($classes), ...$functions] as $reflection) {
            foreach ($reflection->getAttributes(AccessPolicyInterface::class, ReflectionAttribute::IS_INSTANCEOF) as $attribute) {
                yield $attribute->newInstance();
            }
        }
    }
}
