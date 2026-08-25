<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Security;

use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use AccessControl\DecisionVote;
use AccessControl\Exception\AccessDeniedException;
use AccessControl\Requester\RequesterProviderInterface;
use Closure;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use function in_array;
use function is_array;
use function is_object;
use function is_string;

/**
 * Honours Security's #[IsGranted] in an application that no longer has Security.
 *
 * Without this, the attribute is read by nobody once SecurityBundle is gone: no error, no
 * deprecation, and a controller that used to be guarded answers 200. That is the exact shape a
 * migration takes, attributes outliving the bundle that used to handle them, and failing open is
 * the one thing an access control component cannot do.
 *
 * Registered only where Security's own listener is not, so a question is never asked twice.
 *
 * @experimental
 */
final readonly class IsGrantedListener implements EventSubscriberInterface
{
    /**
     * The expression language is optional and only ever used to resolve a subject given as an
     * Expression, which is the one thing PHP lets an attribute carry beyond a plain string.
     */
    public function __construct(
        private RequesterProviderInterface $requesterProvider,
        private AccessPolicyEvaluator $accessPolicyEvaluator,
        private ?ExpressionLanguage $expressionLanguage = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER_ARGUMENTS => ['onKernelControllerArguments', 20],
        ];
    }

    public function onKernelControllerArguments(ControllerArgumentsEvent $event): void
    {
        $context = new AccessPolicyContext(
            $this->requesterProvider->getRequester(),
            $event->getNamedArguments(),
            [
                'request' => $event->getRequest(),
                'args' => $event->getArguments(),
            ],
            self::originOf($event->getController()),
        );

        foreach ($event->getAttributes(IsGranted::class) as $attribute) {
            $this->enforce($attribute, $context, $event);
        }
    }

    /**
     * A subject given as a string names a controller argument, which is what an Argument reference
     * says here. A bare string would be a literal subject instead, so translating it as one would
     * quietly change what the voters are asked about.
     *
     * An Expression or a Closure is resolved on the spot, as Security resolves it, the voters being
     * asked about the value it yields rather than about the expression.
     */
    private function translate(IsGranted $attribute, ControllerArgumentsEvent $event): AccessPolicy
    {
        $subject = $attribute->subject;

        if (is_array($subject)) {
            $named = [];
            foreach ($subject as $key => $reference) {
                $named[is_string($key) ? $key : (string) $reference] = $this->resolve($reference, $event);
            }
            $subject = $named;
        } elseif ($subject !== null) {
            $subject = $this->resolve($subject, $event);
        }

        return new AccessPolicy($attribute->attribute, $subject, message: $attribute->message);
    }

    private function resolve(mixed $reference, ControllerArgumentsEvent $event): mixed
    {
        if ($reference instanceof Closure || $reference instanceof Expression) {
            return $event->evaluate($reference, $this->expressionLanguage);
        }

        return new Argument((string) $reference);
    }

    /**
     * The request is read here rather than through a When composite: the point is to reproduce what
     * Security did with this very attribute, not to restate it in the component's own words.
     */
    private function enforce(IsGranted $attribute, AccessPolicyContext $context, ControllerArgumentsEvent $event): void
    {
        if ($attribute->methods && ! in_array($event->getRequest()->getMethod(), $attribute->methods, true)) {
            return;
        }

        if ($this->accessPolicyEvaluator->evaluate($this->translate($attribute, $event), $context)->decision !== DecisionVote::ACCESS_DENIED) {
            return;
        }

        $message = $attribute->message ?: 'Access Denied.';

        if ($attribute->statusCode !== null) {
            throw new HttpException($attribute->statusCode, $message, code: $attribute->exceptionCode ?? 0);
        }

        throw new AccessDeniedException($message, $attribute->exceptionCode ?? 403);
    }

    private static function originOf(mixed $controller): string
    {
        return match (true) {
            is_string($controller) => $controller,
            is_array($controller) => (is_object($controller[0]) ? $controller[0]::class : $controller[0]) . '::' . $controller[1],
            default => get_debug_type($controller) . '::__invoke',
        };
    }
}
