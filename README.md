# Access Control Framework

![Build Status](https://github.com/Spomky-Labs/access-control-framework/workflows/📁%20PHP%20CI/badge.svg)

[![Latest Stable Version](https://poser.pugx.org/spomky-labs/access-control-framework/v/stable)](https://packagist.org/packages/spomky-labs/access-control-framework)
[![Total Downloads](https://poser.pugx.org/spomky-labs/access-control-framework/downloads)](https://packagist.org/packages/spomky-labs/access-control-framework)
[![Latest Unstable Version](https://poser.pugx.org/spomky-labs/access-control-framework/v/unstable)](https://packagist.org/packages/spomky-labs/access-control-framework)
[![License](https://poser.pugx.org/spomky-labs/access-control-framework/license)](https://packagist.org/packages/spomky-labs/access-control-framework)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Spomky-Labs/access-control-framework/badge)](https://api.securityscorecards.dev/projects/github.com/Spomky-Labs/access-control-framework)

**Access Control** decides whether a requester is allowed to perform an action on a subject. It is authorization on its
own: voters, combining algorithms, access policies declared as attributes, and decisions that say why they were reached,
none of which needs an authentication stack to exist.

This framework contains a PHP library and a Symfony bundle. Installing the bundle in an application that has Symfony
Security changes nothing you can see: your voters keep being consulted, `#[IsGranted]` is read, `is_granted()` answers in
your templates, and your `security.yaml` stays byte for byte what it was. What changed is who decides.

| Package | Repository |
|---|---|
| `spomky-labs/access-control-lib` | [access-control-lib](https://github.com/spomky-labs/access-control-lib) |
| `spomky-labs/access-control-bundle` | [access-control-bundle](https://github.com/spomky-labs/access-control-bundle) |

Both are read-only subtree splits of this repository. Issues and pull requests belong here.

The whole API is marked `@experimental`. It may change in a minor release, and it will keep doing so until the migration
paths out of Symfony Security are complete.

# Documentation

The documentation can be read on the following website: https://acf.spomky-labs.com/

# Support

I bring solutions to your problems and answer your questions.

If you really love that project and the work I have done or if you want I prioritize your issues, then you can help me
out for a couple of :beers: or more!

[Become a sponsor](https://github.com/sponsors/Spomky)

Or

[![Become a Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/FlorentMorselli)

# Supported Versions

The list of the supported versions is available [on this page](https://github.com/Spomky-Labs/access-control-framework/blob/1.0.x/RELEASES.md).

# Contributing

If you discover a security vulnerability within the project, please **don't use the bug tracker and don't publish it
publicly**.
Instead, all security issues must be sent via the [GitHub Vulnerability Report system](https://github.com/Spomky-Labs/access-control-framework/security).

# Licence

This project is release under [MIT licence](LICENSE).
