# Security policy

## Supported versions

Security fixes go to the `main` branch and, once releases exist, the latest
release. Older releases are not patched.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/0xD34DC0D3/voodoo/security/advisories/new)
("Report a vulnerability" on the repository's Security tab). Do not open a
public issue, pull request or discussion for a suspected vulnerability.

Include what you can: the affected version or commit, steps to reproduce, and
the impact you expect.

What to expect:

- an acknowledgement within 7 days;
- an assessment and, if confirmed, a fix plan as soon as practical;
- credit in the advisory if you want it.

voodoo is maintained on a best-effort basis; there is no bug bounty.

## Scope

In scope: the voodoo server and CLI in this repository, and the reference
deployment files in `deploy/`. Behaviour documented as a non-goal in the README
(for example, voodoo not enforcing per-app authorization, or an admin's API key
carrying admin rights) is not a vulnerability by itself.
