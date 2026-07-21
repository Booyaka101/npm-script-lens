# Changelog

## 0.3.0 (2026-07-21)

- **Behavioral upgrade diff**: in `--diff` mode, packages that changed version
  are compared against the base version's analysis and the report calls out
  **capabilities the upgrade gained** — the fingerprint of a hijacked release.
- **`sync` command**: reconcile the `allowScripts` block in package.json with
  the lockfile. Stale entries dropped, upgrades re-pinned (previous decisions
  preserved when nothing was gained, flagged for re-review otherwise), new
  packages added. `--write` applies, `--check` gates CI.
- **`approve` command**: interactive, evidence-driven approval — steps through
  risky packages and writes decisions to package.json.
- **Trust context**: risky packages are enriched with publish age, weekly
  downloads, maintainer count, and sigstore provenance; every audited package
  is checked against OSV — `MAL-*` advisories render as ⛔ KNOWN MALICIOUS,
  always `false` in allowScripts, and fail `--fail-on-high`.
- **Via chains**: reports show how a package entered the tree
  (`via prisma → @prisma/engines`), derived from lockfile dependency edges in
  all supported formats.
- **`--offline`**: analyze packages from `node_modules` on disk — air-gapped
  audits, zero network.
- **`bun.lock` support** (text lockfile; JSONC tolerated).
- **MCP server** (`npm-script-lens mcp`): stdio server with `audit_package`
  and `audit_lockfile` tools so AI coding agents can audit a package before
  adding it as a dependency.

## 0.2.0 (2026-07-21)

- **yarn and pnpm lockfiles**: `yarn.lock` (classic v1 and berry) and
  `pnpm-lock.yaml` (v5/v6/v9 formats) are parsed alongside
  `package-lock.json`/`npm-shrinkwrap.json`; directories are searched for all
  four. Non-registry entries (`file:`/`link:`/`workspace:`/`patch:`/git) are
  skipped, classic-yarn `npm:` aliases resolve to the real package.
- **Obfuscation detection** (new `obf:` signal class, scores HIGH): `eval()`,
  `new Function()`, `vm`, string-built `require()` specifiers (concatenation /
  template interpolation), `atob`/`Buffer.from(…, 'base64')` decoding, and
  bulk `String.fromCharCode` payload building.
- **`--diff <base-lockfile>`**: audit only packages added or upgraded relative
  to a base lockfile — built for PR workflows (also an Action input,
  `diff-base`).
- **`--sarif <file>`**: SARIF 2.1.0 output for GitHub code scanning, results
  anchored to the package's line in the lockfile (Action input `sarif-file`).
- **On-disk result cache** keyed `name@version` + tool version (published
  tarballs are immutable); repeat audits skip the network entirely.
  `--no-cache` disables, `NPM_SCRIPT_LENS_CACHE_DIR` relocates.
- Action `path` input now defaults to `.` and auto-detects the lockfile type.

## 0.1.0 (2026-07-21)

Initial release.

- `audit` command: registry fetch → in-memory tarball index → static analysis
  of `preinstall`/`install`/`postinstall` scripts and the JS files they run
  (relative `require`/`import` chains, `node -e` bodies,
  `path.join(__dirname, …)` indirections, `npm run` recursion; depth ≤ 3).
- Risk ladder HIGH (exec) / MEDIUM (network) / LOW (fs/env) / SAFE, with a
  version-pinned `allowScripts` suggestion block per npm v12.
- Implicit `node-gyp rebuild` detection for packages shipping a root
  `binding.gyp` with no install script.
- Composite GitHub Action: job summary, PR comment, `fail-on-high` gate.
