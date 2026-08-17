<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\When;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\ExpressionLanguage\Expression;

#[When(new Expression('input.getOption("force")'), [new AccessPolicy('ROLE_SUPER_ADMIN')])]
final class ConditionalPolicyCommand extends Command
{
    public function __construct()
    {
        parent::__construct('app:conditional');

        $this->addOption('force', null, InputOption::VALUE_NONE);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        return self::SUCCESS;
    }
}
