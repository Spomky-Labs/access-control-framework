<?php

declare(strict_types=1);

namespace AccessControl;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage as BaseExpressionLanguage;

if (!class_exists(BaseExpressionLanguage::class)) {
    throw new \LogicException(\sprintf('The "%s" class requires the "ExpressionLanguage" component. Try running "composer require symfony/expression-language".', ExpressionLanguage::class));
}

// Help opcache.preload discover always-needed symbols
class_exists(ExpressionLanguageProvider::class);

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
class ExpressionLanguage extends BaseExpressionLanguage
{
    /**
     * The default provider is prepended so that an application can override any of its functions
     * simply by registering a provider of its own.
     */
    public function __construct(?CacheItemPoolInterface $cache = null, array $providers = [])
    {
        array_unshift($providers, new ExpressionLanguageProvider());

        parent::__construct($cache, $providers);
    }
}
