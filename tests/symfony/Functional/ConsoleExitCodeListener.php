<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Exception\AccessDeniedExceptionInterface;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\Console\Event\ConsoleErrorEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

/**
 * What an application writes when 113 is not the exit code its scripts expect.
 *
 * This is the escape hatch the component leans on rather than carrying an exit code of its own:
 * the console already owns the question, and setExitCode() writes the value onto the exception as
 * well, which is what makes Application::run() report it.
 */
#[AsEventListener(ConsoleEvents::ERROR)]
final class ConsoleExitCodeListener
{
    public const int EXIT_CODE = 77;

    public function __invoke(ConsoleErrorEvent $event): void
    {
        if ($event->getError() instanceof AccessDeniedExceptionInterface) {
            $event->setExitCode(self::EXIT_CODE);
        }
    }
}
