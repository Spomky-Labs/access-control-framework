# Access Control Framework

**Access Control** decides whether a requester is allowed to perform an action on a subject. It is authorization on its own: voters, combining algorithms, access policies declared as attributes, and decisions that say why they were reached, none of which needs an authentication stack to exist.

This is the main repository. It is split into two read-only packages on release:

| Package | Repository | What it is |
|---|---|---|
| `spomky-labs/access-control-lib` | [access-control-lib](https://github.com/spomky-labs/access-control-lib) | The library, usable in any PHP application |
| `spomky-labs/access-control-bundle` | [access-control-bundle](https://github.com/spomky-labs/access-control-bundle) | The Symfony integration |

## Installation

```bash
composer require spomky-labs/access-control-bundle
```

Register the bundle in `config/bundles.php`. There is no `enabled` flag: registering it is the opt-in.

```php
return [
    // ...
    AccessControl\Bundle\AccessControlBundle::class => ['all' => true],
];
```

## The two migrations, and why they are two

**Day one is free.** `composer require`, register the bundle, done. The configuration does not move, the code does not move, the answers do not move, but it is this component that decides. Your voters keep being consulted, `#[IsGranted]` is read here, `is_granted()` answers in your templates, and `security.access_control` rules are enforced here. A `security.yaml` stays byte for byte what it was.

**Then, at your own pace.** Move to this component's own vocabulary: its `VoterInterface`, its `#[AccessPolicy]` attribute, its XACML combining algorithms (`permit_overrides`, `deny_overrides`, `majority`, `first_applicable`), and its `access_control` configuration key for an application that no longer has Security at all.

An application is tested in the three shapes the migration goes through: SecurityBundle alone, both bundles, this bundle alone. The first two say the migration is seamless, the third says the destination is reachable.

## Without Symfony Security

The component decides without a token, without a user, and without a firewall. A requester is whatever your application says it is: a machine actor, a service acting on behalf of someone, an API key. `symfony/security-core` is optional throughout, and the classes that know it live in `AccessControl\Bridge\Security`.

Two things a released Symfony still routes through Security, and what to do about them:

- **`AbstractController::isGranted()` and `denyAccessUnlessGranted()`** raise a `LogicException` asking for SecurityBundle when Security is absent, whichever other stack is registered. Add `AccessControl\Bundle\Controller\AccessControlTrait` to your controller: a trait method wins over the inherited one, so nothing else changes. With Security present the trait defers to it.
- **Workflow guards** are refused at compile time by `FrameworkExtension` unless `symfony/security-core` is installed. Install it and nothing more: `WorkflowGuardPass` replaces the guard listener with one of this bundle's, so the package is present but never used.

## Quality assurance

The project uses the [PHPQA](https://github.com/spomky-labs/phpqa) toolchain.

```bash
castor phpunit     # the test suite
castor ecs-fix     # coding standards
castor rector      # automated refactoring, dry run
castor phpstan     # static analysis
castor deptrac     # layer boundaries
castor prepare-pr  # all of the above before a pull request
```

## Support

I bring solutions to your problems and answer your questions.

If you really love that project and the work I have done or if you want I prioritize your issues, then you can help me out for a couple of :beers: or more!

[![Become a Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/FlorentMorselli)

## Licence

This project is release under [MIT licence](LICENSE).
