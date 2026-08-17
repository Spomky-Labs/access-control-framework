<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class PlainCommand extends Command
{
    public function __construct()
    {
        parent::__construct('app:plain');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        return self::SUCCESS;
    }
}
