<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use AccessControl\Attribute\AccessPolicy;
use Symfony\Component\Console\Command\Command;

final class InvokablePolicyCommand extends Command
{
    public function __construct()
    {
        parent::__construct('app:invokable');
    }

    #[AccessPolicy('ROLE_SUPER_ADMIN', message: 'Nope.')]
    public function __invoke(): int
    {
        return self::SUCCESS;
    }
}
