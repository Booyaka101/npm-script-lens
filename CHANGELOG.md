# Changelog

## 0.6.0 (2026-07-23)

- **npm v12 approve-scripts gap check** (`audit --check-v12-gaps`, Action
  input `check-v12-gaps`): detects the two known bugs in npm v12's
  approve-scripts tooling.
  - `v12-optional-gap` ([npm/cli#9562](https://github.com/npm/cli/issues/9562)):
    optional dependencies with install scripts that
    `npm approve-scripts --allow-scripts-pending` never surfaces but
    `npm ci --strict-allow-scripts` rejects (the fsevents-on-Linux trap).
    Reads `optional`/`hasInstallScript` from package-lock.json, resolves
    script names from registry metadata, and reports any such package missing
    from `allowScripts` (bare-name and version-pinned keys both count).
  - `v12-eglobal-risk` ([npm/cli#9463](https://github.com/npm/cli/issues/9463)):
    `npm install -g <pkg>` lines in `.github/workflows/*.yml` where the
    package has install scripts (per registry metadata) and no
    `--allow-scripts` — there is no post-install approval path in global
    contexts (`approve-scripts` errors EGLOBAL), so the fix is inline:
    `npm install -g --allow-scripts=<pkg> <pkg>`.
  - Findings are severity `warn` (exit 0) and integrate with the existing
    output surfaces: Markdown report, `--json` (`{ findings: [...] }`), and
    `--sarif` (new rules `v12-optional-gap` / `v12-eglobal-risk`, results
    anchored to the lockfile or workflow line).
  - In the Action, the check runs as a separate step gated on the runner's
    npm major version (`check-v12-gaps: auto` runs it when npm is v12+;
    `true`/`false` force). It writes to the job summary, annotates via
    `::warning`, and merges its findings into the SARIF file the audit step
    wrote.

## 0.5.0 (2026-07-21)

- **`manifest` command**: writes a stable, committable receipt of install-time
  behavior (`script-lens.json`) — sorted `name@version` → capability kinds —
  so the git diff of that file is the approval-surface change, reviewable with
  no tooling. `--check` fails CI on drift with a human-readable diff; the
  Action gains a `manifest-check` input that reports drift to the job summary.
  Behavior-only and deterministic (no trust/OSV data), so it changes when
  capabilities change, not popularity. Closes #1 (thanks @raju_dandigam).

## 0.4.0 (2026-07-21)

- **Cross-package bin resolution**: `husky install`-style scripts are no
  longer conservatively HIGH — when a lockfile package with the same name
  owns the bin, its actual bin script is fetched, analyzed, and the row is
  re-scored on real evidence (`bin: husky install → husky@9.1.7`).
- **Payload decoding**: base64 / char-code / eval'd **literal** payloads are
  decoded and re-analyzed, so the report shows what hidden code actually
  does. Runtime-assembled payloads remain flagged-but-opaque.
- **`--deep`** (CLI + Action input `deep`): follow bare `require()`s from
  install-script code into the matching lockfile package's entry file, one
  level deep — closes the curated-helper-list gap for in-tree helpers.

## 0.3.1 (2026-07-21)

- Shorten the Action description to fit the GitHub Marketplace 125-character
  limit. No functional changes.

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
