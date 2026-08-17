<?php

declare(strict_types=1);

namespace AccessControl\Bundle\DependencyInjection;

use Symfony\Bundle\SecurityBundle\SecurityBundle;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\ExpressionLanguage;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use AccessControl\Http\AccessRule;
use AccessControl\Strategy\StrategyInterface;
use AccessControl\VoterInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\HttpFoundation\ChainRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\AttributesRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\HostRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\IpsRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\MethodRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\PathRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\PortRequestMatcher;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\Workflow\Event\GuardEvent;
use Twig\Environment;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
class AccessControlExtension extends Extension
{
    /**
     * The collector is registered whether a profiler is configured or not: without one, nothing
     * references it and it is dropped when unused definitions are removed.
     *
     * Four private parameters exist only for the bridge to read and correct, and are gone once the
     * container is compiled.
     *
     * The three "configured" flags say whether the algorithm and its two rules were chosen or merely
     * defaulted. The bridge reads security.access_decision_manager and points them at it, so that an
     * application that has Security declares its combining algorithm once, where it always did, and
     * an explicit choice is the one thing the bridge may not override.
     *
     * The strategy alias is filled by the bridge with the name security.yaml gives the same
     * algorithm, so the panel shows the developer the word they wrote rather than only the XACML one.
     *
     * The integration map says what the bundle ends up answering and what it leaves where it was.
     * Written here as the shape of an application that has no Security, and corrected by the bridge
     * as it decides. Nothing else says which of the two an application is in, and the two look alike
     * from the outside until a question is answered by the wrong engine.
     *
     * The role hierarchy is declared here only by an application without Security: with one, the
     * bridge points our service at security.role_hierarchy, and declaring it twice is refused there.
     *
     * Two files are loaded on a condition worth naming. The workflow services are only ever reached
     * by WorkflowGuardPass, in an application that has no Security; left unused otherwise, they are
     * removed at compile time. And whether SecurityBundle is actually registered is only knowable
     * from a compiler pass, the container handed to an extension carrying no extension of its own,
     * so the bridge is loaded on the strength of the class being reachable and SecurityBridgePass
     * drops it again when it finds no firewall.
     *
     * That last condition asks class_exists() rather than ContainerBuilder::willBeAvailable(), which
     * reads Composer\InstalledVersions. That registry is global to the process and every autoloader
     * loaded into it contributes, so a test runner shipping its own vendor directory answers for a
     * root package that is not the application's, and the bridge silently stops being loaded. The
     * five conditions above ask the same question the same way.
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        $container->registerForAutoconfiguration(VoterInterface::class)
            ->addTag('access_control.voter');
        $container->registerForAutoconfiguration(StrategyInterface::class)
            ->addTag('access_control.strategy');
        $container->registerForAutoconfiguration(AccessPolicyHandlerInterface::class)
            ->addTag('access_control.policy_handler');

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('access_control.php');
        $loader->load('debug.php');

        $container->setParameter('access_control.default_strategy', $config['default_strategy']);
        $container->setParameter('access_control.allow_if_all_abstain', $config['allow_if_all_abstain']);
        $container->setParameter('access_control.allow_if_equal_granted_denied', $config['allow_if_equal_granted_denied']);
        $container->setParameter('.access_control.strategy_configured', $this->wasConfigured($configs, 'default_strategy'));
        $container->setParameter('.access_control.equal_granted_denied_configured', $this->wasConfigured($configs, 'allow_if_equal_granted_denied'));
        $container->setParameter('.access_control.all_abstain_configured', $this->wasConfigured($configs, 'allow_if_all_abstain'));
        $container->setParameter('.access_control.default_strategy_alias', null);
        $container->setParameter('.access_control.integration', [
            'security_bundle' => false,
            'decisions' => 'component',
            'rules' => $config['rules'] ? 'component' : 'none',
            'is_granted' => class_exists(IsGranted::class) ? 'component' : 'none',
            'twig' => class_exists(Environment::class) ? 'component' : 'none',
            'role_hierarchy' => 'component',
            'bridged_voters' => 0,
        ]);
        $container->setParameter('access_control.role_prefix', $config['role_prefix']);
        $container->setParameter('access_control.role_hierarchy.roles', $config['role_hierarchy']);

        if (class_exists(ExpressionLanguage::class)) {
            $loader->load('expression.php');
        }

        if (class_exists(ConsoleEvents::class)) {
            $loader->load('console.php');
        }

        if (class_exists(Environment::class)) {
            $loader->load('twig.php');
        }

        if (class_exists(IsGranted::class)) {
            $loader->load('is_granted.php');
        }

        if (class_exists(GuardEvent::class) && class_exists(ExpressionLanguage::class)) {
            $loader->load('workflow.php');
        }

        if (class_exists(SecurityBundle::class)) {
            $loader->load('security_bridge.php');
        }

        $this->createRules($config['rules'], $container, $loader);
    }

    /**
     * The options and their meaning are those of security.access_control, so that a rule reads the
     * same on both sides and an application can move one across without rewriting it.
     */
    private function createRules(array $rules, ContainerBuilder $container, PhpFileLoader $loader): void
    {
        if (!$rules) {
            return;
        }

        $loader->load('rules.php');

        $definitions = [];
        $requiresChannel = false;

        foreach ($rules as $rule) {
            if (0 === \count(array_filter($rule))) {
                throw new InvalidConfigurationException('One or more access control rules are empty. Did you accidentally add lines only containing a "-" under "access_control.rules"?');
            }

            $definitions[] = new Definition(AccessRule::class, [
                $this->createRuleMatcher($rule, $container),
                $this->createRulePolicy($rule),
                $rule['requires_channel'],
            ]);

            $requiresChannel = $requiresChannel || null !== $rule['requires_channel'];
        }

        $container->getDefinition('access_control.rule_map')->replaceArgument(0, $definitions);

        if (!$requiresChannel) {
            $container->removeDefinition('access_control.listener.channel');
        }
    }

    private function createRuleMatcher(array $rule, ContainerBuilder $container): Definition|Reference
    {
        if (null !== $rule['request_matcher']) {
            if ($rule['path'] || $rule['host'] || $rule['port'] || $rule['ips'] || $rule['methods'] || $rule['attributes'] || $rule['route']) {
                throw new InvalidConfigurationException('The "request_matcher" option should not be specified alongside other options. Consider integrating your constraints inside your RequestMatcher directly.');
            }

            return new Reference($rule['request_matcher']);
        }

        $attributes = $rule['attributes'];

        if (null !== $rule['route']) {
            if (\array_key_exists('_route', $attributes)) {
                throw new InvalidConfigurationException('The "route" option should not be specified alongside "attributes._route" option. Use just one of the options.');
            }

            $attributes['_route'] = $rule['route'];
        }

        $matchers = [];

        if ($rule['methods']) {
            $matchers[] = new Definition(MethodRequestMatcher::class, [array_map(strtoupper(...), $rule['methods'])]);
        }

        if (null !== $rule['path']) {
            $matchers[] = new Definition(PathRequestMatcher::class, [$rule['path']]);
        }

        if (null !== $rule['host']) {
            $matchers[] = new Definition(HostRequestMatcher::class, [$rule['host']]);
        }

        if ($rule['ips']) {
            foreach ($rule['ips'] as $ip) {
                $container->resolveEnvPlaceholders($ip, null, $usedEnvs);

                if (!$usedEnvs && !self::isValidIps($ip)) {
                    throw new \LogicException(\sprintf('The given value "%s" in the "access_control.rules" config option is not a valid IP address.', $ip));
                }

                $usedEnvs = null;
            }

            $matchers[] = new Definition(IpsRequestMatcher::class, [$rule['ips']]);
        }

        if ($attributes) {
            $matchers[] = new Definition(AttributesRequestMatcher::class, [$attributes]);
        }

        if (null !== $rule['port']) {
            $matchers[] = new Definition(PortRequestMatcher::class, [$rule['port']]);
        }

        return new Definition(ChainRequestMatcher::class, [$matchers]);
    }

    /**
     * The roles of a rule are satisfied by any one of them, which is what Security does inside each
     * of its voters, and AtLeastOneOf is how the component says exactly that. An allow_if joins them
     * as one more branch, so a rule carrying both grants on the expression alone.
     */
    private function createRulePolicy(array $rule): ?Definition
    {
        $accessPolicies = [];

        foreach ($rule['roles'] as $role) {
            $accessPolicies[] = new Definition(AccessPolicy::class, [$role, new Definition(Argument::class, ['request'])]);
        }

        if (null !== $rule['allow_if']) {
            if (!class_exists(Expression::class)) {
                throw new \LogicException('Using the "allow_if" option in "access_control.rules" requires the Expression Language component. Try running "composer require symfony/expression-language".');
            }

            $accessPolicies[] = new Definition(AccessPolicy::class, [
                new Definition(Expression::class, [$rule['allow_if']]),
                new Definition(Argument::class, ['request']),
            ]);
        }

        return match (\count($accessPolicies)) {
            0 => null,
            1 => $accessPolicies[0],
            default => new Definition(AtLeastOneOf::class, [$accessPolicies]),
        };
    }

    private static function isValidIps(string $ips): bool
    {
        $ips = preg_split('/\s*,\s*/', $ips, -1, \PREG_SPLIT_NO_EMPTY);

        if (!$ips) {
            return false;
        }

        foreach ($ips as $cidr) {
            if (!self::isValidIp($cidr)) {
                return false;
            }
        }

        return true;
    }

    private static function isValidIp(string $cidr): bool
    {
        $cidrParts = explode('/', $cidr);

        if (1 === \count($cidrParts)) {
            return false !== filter_var($cidrParts[0], \FILTER_VALIDATE_IP);
        }

        $ip = $cidrParts[0];
        $netmask = $cidrParts[1];

        if (!ctype_digit($netmask)) {
            return false;
        }

        if (filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
            return $netmask <= 32;
        }

        if (filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
            return $netmask <= 128;
        }

        return false;
    }

    /**
     * Whether the application named the option itself, as opposed to inheriting its default. The
     * processed configuration cannot tell the two apart, the raw one can.
     *
     * @param array<array<string, mixed>> $configs
     */
    private static function wasConfigured(array $configs, string $key): bool
    {
        foreach ($configs as $config) {
            if (isset($config[$key])) {
                return true;
            }
        }

        return false;
    }
}
