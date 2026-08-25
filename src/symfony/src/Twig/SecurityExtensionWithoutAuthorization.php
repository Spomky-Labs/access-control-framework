<?php

declare(strict_types=1);

namespace AccessControl\Bundle\Twig;

use LogicException;
use Symfony\Bridge\Twig\Extension\SecurityExtension;
use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;
use function in_array;
use function sprintf;

/**
 * Publishes what Security's Twig extension offers beyond authorization, and nothing else.
 *
 * Registering this bundle is the opt-in, so the two functions this component answers are its own
 * from then on. Leaving both extensions to publish them would not raise anything: measured, Twig
 * silently keeps whichever was initialised last, so the answer would depend on the order of
 * config/bundles.php.
 *
 * The rest is left where it belongs. Impersonation URLs are authentication, which stays with
 * Security, and access_decision() hands back an object of Security's that this component has no
 * counterpart for.
 *
 * Each of them is declared here rather than borrowed from the extension it comes from: Twig reads
 * the owner of a function off the object its callable is bound to, and compiles a call that fails
 * at runtime when that object is not a registered extension. Measured, on access_decision().
 *
 * The cost of declaring them is that a function Security adds later would be left out, so the list
 * is checked against the extension's own and a stranger raises at build time.
 *
 * @experimental
 */
final class SecurityExtensionWithoutAuthorization extends AbstractExtension
{
    /**
     * Answered by the AccessControl component from the moment this bundle is registered.
     */
    public const array TAKEN_OVER = ['is_granted', 'is_granted_for_user'];

    /**
     * Left to Security, and delegated method by method rather than borrowed.
     */
    public const array DELEGATED = [
        'access_decision' => 'getAccessDecision',
        'access_decision_for_user' => 'getAccessDecisionForUser',
        'impersonation_exit_url' => 'getImpersonateExitUrl',
        'impersonation_exit_path' => 'getImpersonateExitPath',
        'impersonation_url' => 'getImpersonateUrl',
        'impersonation_path' => 'getImpersonatePath',
    ];

    public function __construct(
        private readonly SecurityExtension $securityExtension,
    ) {
    }

    public function getFunctions(): array
    {
        $functions = [];

        foreach ($this->securityExtension->getFunctions() as $function) {
            if (in_array($name = $function->getName(), self::TAKEN_OVER, true)) {
                continue;
            }

            if (! isset(self::DELEGATED[$name])) {
                throw new LogicException(sprintf('"%s" publishes a "%s()" function this bundle knows nothing about. Either delegate it in "%s", or take it over in the AccessControl component.', SecurityExtension::class, $name, self::class));
            }

            $functions[] = new TwigFunction($name, $this->{self::DELEGATED[$name]}(...));
        }

        return $functions;
    }

    public function getAccessDecision(mixed $role, mixed $object = null, ?string $field = null): AccessDecision
    {
        return $this->securityExtension->getAccessDecision($role, $object, $field);
    }

    public function getAccessDecisionForUser(UserInterface $user, mixed $attribute, mixed $subject = null, ?string $field = null): AccessDecision
    {
        return $this->securityExtension->getAccessDecisionForUser($user, $attribute, $subject, $field);
    }

    public function getImpersonateExitUrl(?string $exitTo = null): string
    {
        return $this->securityExtension->getImpersonateExitUrl($exitTo);
    }

    public function getImpersonateExitPath(?string $exitTo = null): string
    {
        return $this->securityExtension->getImpersonateExitPath($exitTo);
    }

    public function getImpersonateUrl(string $identifier): string
    {
        return $this->securityExtension->getImpersonateUrl($identifier);
    }

    public function getImpersonatePath(string $identifier): string
    {
        return $this->securityExtension->getImpersonatePath($identifier);
    }
}
