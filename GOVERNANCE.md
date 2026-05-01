# Omega Project Governance

This document defines how the Omega project is governed. It is intentionally
minimal during the pre-1.0 phase and will evolve as the community grows.

## Mission

Omega is an Apache-2.0 SPIFFE-compatible workload identity, AuthZEN-compliant
authorization, OIDC federation, and AI agent identity platform delivered as a
single binary. The project targets CNCF Sandbox donation.

## Roles

### Users

Anyone deploying or evaluating Omega. Users participate by filing issues,
joining discussions, and proposing features.

### Contributors

Anyone who has had a pull request merged. Contributors are credited in
release notes and the git history.

### Maintainers

Maintainers have write access to the repository and are responsible for
reviewing and merging pull requests, cutting releases, and stewarding the
project roadmap. The current maintainer list is in
[MAINTAINERS.md](MAINTAINERS.md).

#### Becoming a maintainer

A contributor may be nominated as a maintainer by an existing maintainer
after sustained, high-quality contributions across multiple subsystems.
Nomination requires:

1. A track record of merged pull requests (typically 10+ over 3+ months).
2. Demonstrated review quality on others' pull requests.
3. Approval by a supermajority (2/3) of existing maintainers.

#### Stepping down

Maintainers who become inactive for 6+ months without notice are moved to
emeritus status by majority vote of the remaining maintainers. Maintainers
may also voluntarily move to emeritus at any time.

## Decision making

The default is lazy consensus on pull requests and issues. A maintainer may
merge a non-controversial change after a +1 from another maintainer or after
72 hours with no objections.

For controversial changes (breaking API, governance, license, project
direction), a public RFC is opened as a GitHub issue with `kind/rfc` label.
Decisions require either:

- Lazy consensus after 7 days with no objections, or
- Supermajority (2/3) vote of maintainers if objections are raised.

Maintainers may delegate routine decisions (CI, dependency bumps, doc fixes)
to any committer.

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Violations are handled by the maintainer team; see the Code of Conduct for
the reporting process.

## Security

Security vulnerability reports follow the process described in
[SECURITY.md](SECURITY.md).

## License and IP

All contributions are licensed under Apache-2.0 (see [LICENSE](LICENSE)).
Omega does not require a CLA. The Apache-2.0 license itself includes a
contributor grant of patent rights, which is sufficient for Omega's needs
and CNCF requirements.

## Changes to governance

This document is itself governed by the same RFC process described above.
Material changes require maintainer supermajority and a 14-day public
comment period.
