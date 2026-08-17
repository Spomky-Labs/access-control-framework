<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class ExecuteLevelPolicyCommand extends Command
{
    public function __construct()
    {
        parent::__construct('app:execute-level');
    }

    #[AccessPolicy('read', new Argument('slug'))]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        return self::SUCCESS;
    }
}
