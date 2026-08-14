# Security Policy

## Supported versions

The latest version published to npm is the only one that gets fixes.

## Reporting a vulnerability

Please **don't** open a public issue for a security problem.

Use GitHub's [private vulnerability reporting](https://github.com/Booyaka101/npm-script-lens/security/advisories/new) instead. Expect a first response within a week.

Please include what you found, how to reproduce it, and what an attacker gets out of it.

## What this touches

Reads lockfiles, and fetches package metadata and tarballs from the public npm registry.

- **It never executes an install script.** That is the entire premise. Packages are inspected statically.
- **Tarballs are fetched from the public npm registry** over HTTPS and extracted to a temporary directory. A crafted tarball that escapes extraction is in scope.
- **`review` shells out to `npm install --dry-run --json`** in your project, to read npm's own pending-approval list. `--dry-run` resolves the tree without running install scripts.
- **`--since` shells out to `git`** in your repository to read the base lockfile from a ref. Read-only.

## Scope

In scope: anything that leaks a credential, reads data belonging to someone else, or lets untrusted input reach code execution.

Out of scope: findings that require an attacker to already control the machine it runs on.
