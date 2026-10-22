# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through GitHub's [private vulnerability reporting](https://github.com/invarislabs/agent-auth/security/advisories/new) for this repository, or by contacting [Invaris Labs](https://www.invarislabs.com/).

Include what you found, how to reproduce it, and the impact you expect. We'll acknowledge reports within a few working days and keep you informed while we fix them. We're happy to credit reporters in the advisory.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | ✅ security fixes |
| < 0.4 | ❌ please upgrade (see [CHANGELOG](CHANGELOG.md) for the fixes in 0.4.0) |

## Audit status

AgentAuth has **not** had an independent security audit. v0.4 was hardened and is tested against the attacks listed in the [threat model](docs/threat-model.md), including adversarial, fuzz and concurrency tests, but that is not a substitute for external review. An audit is planned before 1.0 ([roadmap](docs/roadmap.md)).

## Scope

In scope: the protocol (docs/protocol.md), the Python package, the registry, the Docker image and the deployment configuration in this repository. Known limitations are listed in the threat model; reports showing they're worse than described are welcome.
