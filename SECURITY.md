# Security Policy

## Reporting a vulnerability

Please report security issues in raijin-scan **privately**, using GitHub private vulnerability reporting:

1. Open the [Security tab](https://github.com/protonnegativo/raijin-scan/security) of this repository.
2. Click **Report a vulnerability**.

Please do not open a public issue or pull request for a vulnerability, and do not post it on social media before it is fixed.

Useful details: the version (`raijin-scan --version`), the command line, the input that triggers the problem, what you expected and what happened, and the impact you see.

## What to expect

raijin-scan is maintained by one person in their spare time, so these are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledge your report | within 7 days |
| First assessment (accepted, needs more info, or not a vulnerability) | within 14 days |
| Fix or mitigation for a confirmed issue | within 90 days, sooner for severe issues |
| Public advisory | when the fix is released, crediting you if you want |

If a report is declined, I will say why. If you do not hear back in 14 days, add a comment to the report.

## Supported versions

Only the latest release gets security fixes. Please check that the problem exists in the latest release before reporting.

## Scope

In scope, bugs in this repository's code that let an attacker:

- run code or commands on the machine running raijin-scan through crafted target responses, crafted input files or crafted arguments;
- read or write files outside what the user asked for;
- make raijin-scan send requests outside the scope the user gave (a scope bypass);
- leak credentials or other secrets from the machine running raijin-scan into its output.

Out of scope:

- vulnerabilities in the engines raijin-scan runs underneath (nuclei, httpx, ...): report those to their own projects;
- vulnerabilities in third-party Go modules we depend on, unless raijin-scan uses them in a way that makes them exploitable (otherwise report upstream; Dependabot tracks them here);
- findings that raijin-scan reports about targets you scanned (those are the tool working);
- denial of service by pointing the tool at a very large input or a very slow target;
- problems that need an attacker who already controls the machine or the command line.

## Authorized use only

Raijin is for authorized testing only: your own assets, pentests with written scope, and bug bounty programs within their rules. Every tool takes an explicit scope and refuses targets outside it.

When you research raijin-scan itself, follow the same rule. Test it against your own machine, a local lab or systems you are allowed to test. Do not run it against third parties to prove a point, and do not access, modify or keep data that is not yours. Good-faith research that follows this policy will not get a complaint from me.
