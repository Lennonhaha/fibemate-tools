# FIBEMATE-Tools Security Policy

## Supported Versions

FIBEMATE-Tools is under active development. Only the latest `main` branch is supported.

| Version | Supported |
|---------|-----------|
| main     | ✅        |
| older    | ❌        |

## Reporting a Vulnerability

Email **27202998@qq.com** with details. We respond within 72 hours.

Do **not** open a public issue for security reports.

## Scope

FIBEMATE-Tools contains utility scripts and the Crypto Time Ledger CLI.
Security concerns include:

- Tampering with ledger chain integrity
- Weak hashing in timestamp verification
- Command injection in CLI argument parsing

## Out of Scope

- Cryptographic algorithm correctness (tracked in main `fibemate` repo)
- Server deployment security (tracked in main `fibemate` repo)

## Bug Bounty

We do not operate a paid bounty program. Public credit is given for
confirmed vulnerabilities. This may evolve into a paid program if the
project receives grant or sponsorship funding.

## Dependency Vulnerabilities

Dependabot monitors npm dependencies. Alerts are triaged weekly.
Unpatched transitive dependencies (no upstream fix) are documented in
`dependabot.yml` ignore rules with rationale.