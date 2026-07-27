# Changelog

## 1.2.0 (2026-07-27)

npm v12 flips **three** defaults, not one — this release covers the other two:
`allow-git` and `allow-remote` (both the strict enum `all`|`none`|`root`,
default `none`), under which git and remote-tarball dependencies stop
resolving entirely unless opted in.

- **New `sources` command**: finds every git (`git+ssh`/`git+https`/`git://`,
  `github:`/`gitlab:`/`bitbucket:`) and remote-tarball dependency in the
  lockfile — all four dialects: package-lock v1/v2/v3, yarn classic + berry,
  pnpm, bun.lock — and classifies each as ROOT (declared in the root
  package.json, `allow-git=root` suffices) or TRANSITIVE (forces
  `allow-git=all`, with the via-chain that drags it in). Prints the **minimal
  correct .npmrc** and, when a transitive dep forces `all`, exactly which dep
  to re-point to tighten back to `root`. Pure lockfile+config analysis — no
  network. `--json` emits `{ git, remote, npmrc }`.
- **`sources --check`** (CI gate, exit 1) fails three distinct ways:
  *insufficient* (npm v12 will refuse the install), *over-permissive* (`all`
  committed where `root` suffices — tighten it), and *invalid* — the
  `allow-git=true` that several published migration guides recommend is not in
  the enum and npm treats it as unset. **`sources --write`** merges the
  minimal values into `.npmrc` preserving every other key, comment, and line
  byte-for-byte (npm lockfiles only — surfaced as such for yarn/pnpm/bun).
- **`allow --ci-check` now also fails** when git/remote deps exist and the
  committed config is insufficient or invalid — the same silent-CI-break shape
  as a missing allowScripts block, same fast no-scan gate.
- **`doctor`** reports git/remote dep counts, minimal values vs the committed
  `.npmrc`, whether your npm even has the keys yet (introduced in 11.10.0 /
  11.15.0 — checked at full-version precision), and warns that
  `allow-git=root` is unreliable on npm 11 (npm/cli#9189, closed via PR #9206;
  root-level git deps were wrongly rejected) — recommend `all` there.
- **GitHub Action `sources-check` input** (default `'false'`, opt-in): fails
  the job with an `::error` annotation and a job-summary line when the
  committed `.npmrc` doesn't match the lockfile's git/remote reality.
- New fixtures `v12-git-root`, `v12-git-transitive`, `v12-remote-tarball`;
  the audit/analyzer path is untouched (non-registry deps were and are skipped
  there), so existing reports are byte-identical. 174 tests.

## 1.1.0 (2026-07-25)

- **New `diff` command**: `npm-script-lens diff <pkg>@<old> <pkg>@<new>`
  compares the install-time lifecycle scripts (`preinstall`/`install`/
  `postinstall`) plus the implicit `node-gyp rebuild` (root `binding.gyp`)
  between two registry versions. Prints UNCHANGED (green) / ADDED (red) /
  REMOVED (yellow) / MODIFIED (red, with a line-level diff); `--json` emits
  `{ unchanged, added, removed, modified }`. Exit `1` when any script was added
  or modified (a CI gate for upgrades that grow their install surface), else
  `0`. Reuses `registry.fetchPackage` for fetching + binding.gyp detection.

## 1.0.1 (2026-07-25)

- Fix `audit --since <ref>` on Windows: resolve the base lockfile via
  `git show <ref>:./<file>` from the lockfile's directory instead of computing
  the repo-relative path host-side. The old `path.relative(toplevel, lockfile)`
  broke when git's toplevel and `os.tmpdir()` disagreed on 8.3 short names
  (e.g. `runneradmin` vs `RUNNER~1`), which git rejected as "outside
  repository." Adds a subdirectory (monorepo) regression test.

## 1.0.0 (2026-07-25)

**1.0** — npm-script-lens is now the complete, cross-ecosystem tool for the
install-script-approval problem every package manager now has, reachable from
every surface a developer works in.

- **VS Code extension** (`editors/vscode`): inline install-script risk
  diagnostics on `package.json`, a workspace status-bar summary, and commands
  to audit / generate the allowlist / review / run doctor — a thin, tested UI
  over the CLI engine. Ships a Marketplace-ready icon + gallery banner and a
  Getting-Started **walkthrough** (audit → allowlist → CI); packaged and
  installable (`.vsix`).
- **`sync-check` Action input**: fails the job when the install-script allowlist
  has drifted from the lockfile — cross-ecosystem (npm/pnpm/yarn/bun,
  auto-detected), a stronger companion to `ci-check`.
- **Neovim plugin** (`editors/nvim`): `vim.diagnostic` install-script risk on
  `package.json` + `:NpmScriptLens*` commands; verified loading under headless
  Neovim 0.12.
- **Shareable HTML report**: `audit --html report.html` writes a self-contained,
  script-free dashboard (risk summary, per-package table, allowlist block).
- **Shell completions**: `npm-script-lens completion <bash|zsh|fish>`.
- **Local enforcement**: `init --hook` installs a git pre-commit hook running
  `sync --check`, and the repo ships a `.pre-commit-hooks.yaml` for the
  pre-commit framework.
- The full workflow — **`audit` · `allow` · `review` · `sync` · `approve` ·
  `manifest` · `doctor` · `init`** — works across **npm, pnpm, yarn Berry, and
  bun**, all four verified end-to-end against the real binary, each writing its
  native allowlist (`allowScripts` / `allowBuilds` / `dependenciesMeta` /
  `trustedDependencies`).
- **Governance** (`script-lens.policy.json`): risk ceiling, capability bans,
  age/provenance requirements (trust-enriched for every candidate), and
  per-package waivers with expiry.
- **CI**: `allow --ci-check`, `sync --check`, a GitHub Action, an auto-fix bot
  workflow (`init --auto-fix`), and two self-drift canaries (npm-compat,
  pm-compat).
- **Durability**: a centralized manager contract (`npm-contract` +
  `pm-contract`) and a `doctor` that fails on drift, so the tool stays correct
  as npm/pnpm/yarn/bun evolve.
- **AI agents**: MCP server with `audit_package`, `audit_lockfile`, and
  `classify_allowscripts`.

Reaching 1.0 from the v0.5 release spanned: cross-ecosystem allow/review/sync,
policy, init, doctor, `--since`, the MCP allow tool, the canaries, and the
editor extension. 124 tests.

## 0.12.0 (2026-07-25)

- **Auto-fix bot**: `init --auto-fix` scaffolds a workflow that, on
  Renovate/Dependabot branches, runs `sync --write` and commits the reconciled
  allowlist back — so a dependency bump can't silently leave the branch with an
  uninstallable allowlist.
- **Policy age/provenance now enforce for every package**: a policy with
  `minAgeDays` or `requireProvenance` triggers trust enrichment for *all*
  scripted packages (previously only HIGH/MEDIUM had trust data), so those
  rules work on LOW packages too. With `--no-trust` the rules fail closed (an
  unverifiable package is held for review, never auto-approved).

## 0.11.0 (2026-07-25)

The whole workflow is cross-ecosystem, governable, and one command to adopt.

- **`review` and `sync` now speak every package manager**, joining `allow`.
  They auto-detect the manager, read its existing native allowlist for
  coverage, and write decisions back in the right format/file (npm
  `allowScripts` · pnpm `allowBuilds` · yarn `dependenciesMeta.built` · bun
  `trustedDependencies`). `--manager` overrides detection on all three.
- **All four managers are now verified end-to-end against the real binary**
  (npm, pnpm 11, yarn Berry 4, bun 1.3): `allow --write` generates the native
  allowlist and the manager then runs a previously-blocked install script.
- **Governance policy** (`script-lens.policy.json`, or `--policy <file>`):
  codify what auto-approves instead of the fixed SAFE/LOW heuristic —
  `autoApprove.maxRisk`, `denyCapabilities` (never auto-approve a given
  exec/net/fs/… capability), `minAgeDays` and `requireProvenance` (need trust
  data), and per-package `waivers` with a reason and an `expires` date. With no
  policy file, behavior is exactly the built-in default. Honored by `allow`,
  `review`, and `sync`.
- **`init`**: scaffolds `script-lens.policy.json` + a ready-to-commit CI
  workflow (audit + `allow --ci-check` gate) in one command; skips existing
  files unless `--force`.
- **`classify_allowscripts` MCP tool** and the CLI share one decision engine,
  so agents get the same policy-aware split.
- **pm-compat canary** (`.github/workflows/pm-compat.yml`): a scheduled matrix
  (npm/pnpm/bun) that drives each real manager through `allow --write` and
  asserts the approved script runs — the cross-ecosystem drift tripwire.
- **`src/pm-contract.js`** gained `readExisting`/`covers` (coverage),
  `writeDecisions` (true/false where the format allows) and `writeFull`
  (replace, so `sync` can drop stale entries) per manager.

## 0.10.0 (2026-07-24)

Cross-ecosystem release — install-script approval isn't an npm-only problem
anymore, so `allow` isn't npm-only anymore.

- **`allow` now speaks every major package manager's native allowlist**, auto-
  detected from the lockfile:
  - **npm** → `allowScripts` (`"pkg@1.2.3": true`) in package.json
  - **pnpm** → `allowBuilds` (`pkg: true`) in pnpm-workspace.yaml (pnpm ≥ 10.26
    / v11; older pnpm 10 uses the `onlyBuiltDependencies` array)
  - **yarn Berry** → `dependenciesMeta.<pkg>.built: true` in package.json
    (+ `enableScripts: false` in .yarnrc.yml)
  - **bun** → `trustedDependencies: ["pkg"]` in package.json
  The same SAFE/LOW→approve, MEDIUM/HIGH/malicious→`_review` policy and the same
  behavioral analysis drive all four; only the emitted format differs. stdout is
  the manager's native block, directly pasteable.
- **`allow --write`** merges the auto-approved entries into the right file for
  the detected manager (package.json / pnpm-workspace.yaml / .yarnrc.yml),
  preserving everything else. The pnpm-workspace.yaml merge is comment- and
  key-preserving with no YAML dependency.
- **`allow --manager <npm|pnpm|yarn|bun>`** overrides auto-detection.
- **Safety notes surfaced**: bun's `trustedDependencies` *replaces* bun's built-
  in trusted list (so default-trusted scripted deps can be dropped) — `allow`
  warns; yarn needs `enableScripts: false` to be an allowlist — `allow --write`
  sets it.
- **`doctor`** now reports the detected package manager and which allowlist file
  `allow` will target.
- **`src/pm-contract.js`**: one adapter per manager (detect / key / render /
  write), so adding or tracking a manager's format is a single-file change.
- Verified end-to-end against **real pnpm 11**: `allow --write` generated a
  `pnpm-workspace.yaml` that pnpm accepted and used to run an approved package's
  install script. npm is likewise live-verified; yarn/bun formats are verified
  against their official docs and unit-tested (those binaries weren't installed
  in the build environment).

## 0.9.0 (2026-07-24)

Durability release — keeping the tool useful as npm itself changes.

- **`doctor` command**: probes your local npm and reports, check by check,
  whether the npm contract this build assumes still holds — npm version,
  allowScripts enforcement, a parser self-test against the canonical dry-run
  shapes, a live `npm install --dry-run --json` shape check, the assumed
  contract, and each detector's upstream status. Exits 1 on genuine drift (an
  unrecognized output shape). `--json` for machine output; `--no-live`/
  `--offline` skip the live probe.
- **Loud drift detection**: `review` no longer silently treats an unfamiliar
  npm output as "nothing pending". A v12+ npm whose `--dry-run --json` shape
  isn't recognized now warns and falls back to the lockfile, pointing at
  `doctor`.
- **npm-compat canary** (`.github/workflows/npm-compat.yml` +
  `scripts/npm-compat-canary.js`): a scheduled matrix over npm `12`/`latest`/
  `next` that drives the **real** npm (not the test stubs) against a scratch
  project and fails on drift — the automated tripwire the unit tests can't be.
- **Centralized npm contract** (`src/npm-contract.js`): every npm coupling —
  field name, version threshold, dry-run args, `unreviewedScripts` key, summary
  keys, command/flag names, and the detector upstream-status table — lives in
  one file, so a future npm change is a one-file patch.
- **Version-aware v12 gap detectors**: the gap report now states which local
  npm it checked against, and each finding carries its upstream issue and fix
  status (e.g. npm/cli#9463's fix landing in `c14e87c`).
- **`audit --since <git-ref>`**: like `--diff`, but extracts the base lockfile
  from a git ref (branch/tag/SHA) automatically — audit only what changed since
  then, ideal for Renovate/Dependabot branches.
- **`classify_allowscripts` MCP tool**: agents can get the `allow` split
  (`{allowScripts, _review}`) non-interactively over the existing MCP server.

## 0.8.0 (2026-07-24)

- **`allow` subcommand**: one-shot split of every package with install-time
  scripts into a pre-approved `allowScripts` block (behavioral risk SAFE/LOW,
  not known-malicious) and a `_review` list (MEDIUM/HIGH, known-malicious, or
  un-fetchable). Emits `{ "allowScripts": { … }, "_review": [ … ] }` as JSON on
  stdout and an `X packages auto-approved, Y need manual review.` summary on
  stderr. `--input <audit.json>` classifies a saved `audit --json` result
  instead of re-running the scan. `--write` merges the auto-approved entries
  into `package.json` (preserving existing keys); `_review` packages are left
  out so a human still decides on them.
- **`allow --ci-check`**: a fast CI guard (no scan) that exits `1` when a
  workflow in `.github/workflows/` runs `npm install`/`i`/`ci`, `package.json`
  has no `allowScripts` block, and the local npm is v12+ (probed via
  `npm --version`) — the exact combination where npm v12 silently skips every
  dependency's install scripts. Passes with a one-line reason otherwise.
- **GitHub Action `ci-check` input** (default `'false'`, opt-in): runs the
  `allow --ci-check` gate as a fail-fast composite step (`if: always()`), so the
  same npm-v12 break check fails the job with a `::error` annotation and a job
  summary line. Shares one detection function with the CLI (`ciCheckResult`).

## 0.7.0 (2026-07-24)

- **`review` subcommand**: lists packages with pending npm v12 approve-scripts
  approvals alongside the actual install-script content, so you can see exactly
  what each lifecycle script would run before allowing it.

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
