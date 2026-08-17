<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\When;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\ExpressionLanguage\Expression;

#[AsCommand(name: 'app:access-controlled')]
#[When(new Expression('input.getOption("destructive")'), [new AccessPolicy('DELETE')], message: self::DENIAL)]
class AccessControlledCommand extends Command
{
    /**
     * Carried by the When rather than by the policy it wraps, which is how an application says
     * something of its own about a refusal that only happens at this entry point.
     */
    public const DENIAL = 'Only maintainers may delete.';

    protected function configure(): void
    {
        $this->addOption('destructive', null, InputOption::VALUE_NONE);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('done');

        return self::SUCCESS;
    }
}
