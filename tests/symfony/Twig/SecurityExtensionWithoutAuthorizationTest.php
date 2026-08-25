<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Twig;

use AccessControl\Bundle\Twig\SecurityExtensionWithoutAuthorization;
use Closure;
use PHPUnit\Framework\TestCase;
use ReflectionFunction;
use Symfony\Bridge\Twig\Extension\SecurityExtension;
use Symfony\Component\Security\Core\Authorization\AccessDecision;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\UserAuthorizationCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\TwigFunction;
use function sprintf;

final class SecurityExtensionWithoutAuthorizationTest extends TestCase
{
    /**
     * The two functions the component answers are gone, the six others are still published. Leaving
     * both extensions to publish is_granted() would raise nothing: Twig keeps whichever was
     * initialised last, so the answer would follow the order of config/bundles.php.
     */
    public function testItPublishesEverythingButTheTwoTheComponentAnswers()
    {
        static::assertSame([
            'access_decision',
            'impersonation_exit_url',
            'impersonation_exit_path',
            'impersonation_url',
            'impersonation_path',
            'access_decision_for_user',
        ], $this->namesOf(new SecurityExtensionWithoutAuthorization($this->securityExtension())));
    }

    /**
     * And each is bound to this extension rather than borrowed from the one it comes from. Twig
     * reads the owner of a function off the object its callable is bound to, and compiles a call
     * that fails at runtime when that object is not a registered extension. Measured on
     * access_decision(), which raised "the SecurityExtension extension is not enabled".
     */
    public function testEachFunctionIsBoundToThisExtension()
    {
        $extension = new SecurityExtensionWithoutAuthorization($this->securityExtension());

        foreach ($extension->getFunctions() as $function) {
            $callable = $function->getCallable();

            static::assertInstanceOf(Closure::class, $callable);
            static::assertSame($extension, new ReflectionFunction($callable)->getClosureThis(), sprintf('"%s()" is bound elsewhere.', $function->getName()));
        }
    }

    /**
     * The list is written by hand, so it has to be checked against the one it mirrors: a function
     * Security adds later would otherwise be dropped without a word. This is the test that fails
     * the day it happens, and the extension raises at build time for the same reason.
     */
    public function testTheListCoversEverythingSecurityPublishes()
    {
        $published = $this->namesOf($this->securityExtension());
        $known = array_merge(SecurityExtensionWithoutAuthorization::TAKEN_OVER, array_keys(SecurityExtensionWithoutAuthorization::DELEGATED));

        sort($published);
        sort($known);

        static::assertSame($published, $known, 'Security publishes a function this bundle neither takes over nor delegates.');
    }

    /**
     * @return list<string>
     */
    private function namesOf(SecurityExtension|SecurityExtensionWithoutAuthorization $extension): array
    {
        return array_map(static fn (TwigFunction $function) => $function->getName(), $extension->getFunctions());
    }

    /**
     * Built as the bundle builds it, with a checker that answers for another user: the two
     * "for_user" functions are published only then, and leaving them out would make this file agree
     * with itself while missing half of what it checks.
     */
    private function securityExtension(): SecurityExtension
    {
        return new SecurityExtension(new class() implements AuthorizationCheckerInterface, UserAuthorizationCheckerInterface {
            public function isGranted(mixed $attribute, mixed $subject = null, ?AccessDecision $accessDecision = null): bool
            {
                return false;
            }

            public function isGrantedForUser(UserInterface $user, mixed $attribute, mixed $subject = null, ?AccessDecision $accessDecision = null): bool
            {
                return false;
            }
        });
    }
}
