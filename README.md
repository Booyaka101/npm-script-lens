# npm-script-lens

**Know what an install script actually does before you approve it.**

_The install-script-approval tool for **npm · pnpm · yarn · bun** — from your **CLI**, **CI**, **editor**, and **AI agent**._

Since [npm v12 (July 8, 2026)](https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/), dependency lifecycle scripts (`preinstall`, `install`, `postinstall`) and implicit `node-gyp` builds **no longer run unless explicitly allowed** via the `allowScripts` field in `package.json`. And npm isn't alone — **pnpm** (`allowBuilds`), **yarn** Berry (`dependenciesMeta.built`), and **bun** (`trustedDependencies`) all made install scripts opt-in too. That leaves every team, on every package manager, staring at a list of package names asking: *which of these are safe to approve?*

`npm-script-lens` answers that with evidence, not vibes — the review-report mode the community asked for in [npm/rfcs#897](https://github.com/npm/rfcs/pull/897). For every package in your lockfile — `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and berry), `pnpm-lock.yaml`, or `bun.lock` — it:

1. fetches the version metadata from the public npm registry,
2. stream-downloads the tarball and indexes its source files (`tar-stream`, nothing written to disk) — skipped entirely for the majority of packages with no install-time scripts, which is why real audits take seconds,
3. statically analyzes each `preinstall`/`install`/`postinstall` script with `acorn` — including the JS the script actually runs: `node <file>` targets, `node -e` eval bodies, relative `require()`/`import` chains, `path.join(__dirname, …)` indirections, and `npm run <target>` recursion into the package's own scripts (3 levels deep, cycle-safe). Packages that ship a root `binding.gyp` with no install script get their **implicit `node-gyp rebuild`** surfaced too — npm v12 blocks those builds as well. (`prepare` is deliberately excluded: npm never runs it for registry-installed deps, and flagging leftover `"prepare": "husky install"` lines would be noise.)
4. scores the behavior and emits a Markdown report plus a **ready-to-paste, version-pinned `allowScripts` block**,
5. adds context to every risky package: **how it entered your tree** (`via prisma → @prisma/engines`), **whether OSV lists it as malicious** (⛔ hard flag, always denied), and **publisher trust signals** — publish age, weekly downloads, maintainer count, sigstore provenance — so "🔴 HIGH, 74M dl/wk, 10 years old" reads differently from "🔴 HIGH, published 4 days ago, 12 dl/wk".

| Risk | Meaning |
|---|---|
| 🔴 HIGH | spawns processes (`child_process`, `execa`, `node-gyp`, unresolved binaries) **or runs constructed code** (`eval`, `new Function`, `vm`, string-built `require()`, base64/char-code payload decoding) |
| 🟠 MEDIUM | network access (`http(s).get/request`, `fetch`, `axios`/`got`/`node-fetch`/…) without exec |
| 🟡 LOW | filesystem writes or `process.env` reads only |
| 🟢 SAFE | none of the above |

Results are cached on disk keyed `name@version` + tool version (published tarballs are immutable), so repeat audits are near-instant and fully offline. `--no-cache` opts out; `NPM_SCRIPT_LENS_CACHE_DIR` relocates the cache.

## CLI

```bash
npx npm-script-lens audit --path ./my-project --fail-on-high
# --path PATH   project dir or lockfile: package-lock.json, npm-shrinkwrap.json,
#               yarn.lock, pnpm-lock.yaml, bun.lock (default: .)
# --json        machine-readable output
# --out FILE    write report to a file
# --sarif FILE  also write SARIF 2.1.0 for GitHub code scanning
# --html FILE   also write a self-contained, shareable HTML report
# --diff BASE   audit only packages added/upgraded vs a base lockfile
# --since REF   like --diff, but extract the base lockfile from a git ref
# --offline     analyze node_modules on disk instead of the registry
# --no-trust    skip OSV/downloads/provenance enrichment
# --no-cache    disable the on-disk result cache
# --fail-on-high  exit 1 if any package scores HIGH or is known malicious
```

Reviewing a PR? Audit only what changed — and see what **upgrades gained**:

```bash
npx npm-script-lens audit --since origin/main --fail-on-high   # base lockfile pulled from the ref for you
# …or point --diff at a base lockfile you extracted yourself:
git show origin/main:package-lock.json > /tmp/base-lock.json
npx npm-script-lens audit --diff /tmp/base-lock.json --fail-on-high
```

In diff mode, a package that was already in the tree but changed version is compared against the base version's analysis: `**⚠️ gained vs 1.2.0:** net: fetch()` is the fingerprint of a hijacked release (event-stream, the 2025 Shai-Hulud wave); `no new capabilities vs 1.2.0` is a boring upgrade.

## diff: what did an upgrade change in the install scripts?

Before you bump a pin, see exactly which install-time behavior a new version adds or changes — the surface npm v12 will ask you to re-approve. `diff` compares the `preinstall`/`install`/`postinstall` scripts (and the implicit `node-gyp rebuild` that ships with a root `binding.gyp`) between two versions, straight from the registry:

```bash
npx npm-script-lens diff sharp@0.32.6 sharp@0.33.0
# --json   emit { unchanged, added, removed, modified } instead of colored text
```

```
sharp@0.32.6 → sharp@0.33.0
REMOVED: implicit node-gyp rebuild (binding.gyp)
MODIFIED: install
    - (node install/libvips && node install/dll-copy && prebuild-install) || …
    + node install/check
```

- **UNCHANGED** (green) — key present in both, byte-identical
- **ADDED** (red) — a new script, or a gained `binding.gyp` → `ADDED: implicit node-gyp rebuild (binding.gyp)`
- **REMOVED** (yellow) — a script that went away
- **MODIFIED** (red) — same key, changed content, with a line-level diff

Exit `0` when everything is unchanged; exit `1` the moment any script is **added or modified** — so a Renovate/Dependabot CI step can fail the moment an upgrade grows its install-time surface. (A pure removal stays exit `0`.)

## review: see what you're approving, not just its name

npm v12's own pending list stops at the script *command*:

```
$ npm approve-scripts --allow-scripts-pending
sharp@0.33.5   install: node install/check
```

What's inside `install/check`? npm can't tell you — [the #1 complaint in the v12 migration discussion](https://github.com/orgs/community/discussions/198547). `review` picks up exactly where npm stops:

```bash
npx npm-script-lens review                        # show every pending approval with evidence
npx npm-script-lens review --output-allowscripts  # …and write the decisions into package.json
```

For each package awaiting an `allowScripts` decision it shows the script command, the **first 40 lines of the actual file the command runs** (from the version-pinned registry tarball — or `node_modules` with `--offline`), the behavioral scan verdict with signals, the OSV malware check, and publisher trust:

```
── sharp@0.33.5  [🔴 HIGH]
   1.9y old · 75M dl/wk · 1 maintainer · no provenance
   OSV: no known malicious advisories
   install: node install/check
     exec: node-gyp rebuild --directory=src
     exec: require('child_process')
   ┌─ install/check.js (first 40 of 42 lines)
   │   1  // Copyright 2013 Lovell Fuller and others.
   │   2  // SPDX-License-Identifier: Apache-2.0
   …
```

The pending set comes from your own npm when it can answer: with npm ≥ 12, `review` runs `npm install --dry-run --json` and reads its `unreviewedScripts` — so what you review is literally what npm would block, even before a lockfile exists. On npm < 12 (or `--offline`) it computes the same set from the lockfile minus your `allowScripts` entries (bare-name and pinned keys both count, and `false` is a decision too — matching npm v12's semantics exactly).

`--output-allowscripts` merges version-pinned entries for every reviewed package into `package.json`, preserving existing decisions: SAFE/LOW default to `true`, HIGH/MEDIUM and OSV-flagged packages to `false` — flip after reading the evidence. `--json` emits the whole review (pending, risk, content, suggested block) for scripting. `NPM_SCRIPT_LENS_NPM` overrides which npm the dry-run uses.

## allow: pre-approve the safe packages, hold the risky ones — in any package manager

`allow` runs the scan and splits every package that has install-time scripts into two buckets — the ones behavioral analysis found harmless (SAFE/LOW) go straight into the allowlist; everything that spawns processes, reaches the network, is known-malicious, or couldn't be fetched (MEDIUM/HIGH) is held back in a `_review` list for a human. It emits the block in **your package manager's native format**, auto-detected from the lockfile, on stdout — with a one-line summary on stderr:

```bash
npx npm-script-lens allow                     # scan, print the native allowlist block + _review
npx npm-script-lens allow --write             # …and merge the auto-approved entries into the right file
npx npm-script-lens allow --manager pnpm      # force a manager instead of auto-detecting
npx npm-script-lens allow --input audit.json  # classify a saved `audit --json` result, no rescan
```

Every major package manager adopted the same "scripts are opt-in, keep an allowlist" model. `allow` writes each one's native format — same risk policy, same analysis, different file:

| manager | allowlist | file | `allow --write` target |
|---|---|---|---|
| **npm** 12 | `allowScripts: { "pkg@1.2.3": true }` | package.json | package.json |
| **pnpm** 10.26+/11 | `allowBuilds: { pkg: true }` | pnpm-workspace.yaml | pnpm-workspace.yaml (comment-preserving) |
| **yarn** Berry | `dependenciesMeta.<pkg>.built: true` | package.json | package.json + `enableScripts: false` in .yarnrc.yml |
| **bun** | `trustedDependencies: ["pkg"]` | package.json | package.json |

```jsonc
// npm project → allowScripts (version-pinned)
{ "allowScripts": { "core-js@3.38.1": true }, "_review": ["sharp@0.32.6"] }
// pnpm project → allowBuilds (by name)
{ "allowBuilds": { "core-js": true }, "_review": ["sharp@0.32.6"] }
```

```
1 package auto-approved, 1 need manual review. (pnpm — allowlist in pnpm-workspace.yaml)   ← stderr
```

> **bun caveat** (surfaced automatically): defining `trustedDependencies` *replaces* bun's built-in trusted list, so packages bun trusted by default (esbuild, sharp…) stop running scripts unless listed. **yarn** needs `enableScripts: false` to turn `dependenciesMeta` into an allowlist — `allow --write` sets it for you.

### CI guard

`allow --ci-check` runs **no scan** — it's a fast gate for CI. It exits `1` when all three are true: a workflow in `.github/workflows/` runs `npm install`/`npm i`/`npm ci`, `package.json` has no `allowScripts` block, and the local npm is v12+ (probed via `npm --version`). That is exactly the combination where npm v12 will silently skip every dependency's install scripts and your build breaks with no obvious cause.

```bash
npx npm-script-lens allow --ci-check
# CI will break on npm v12: run lens allow to generate allowScripts block.  (exit 1)
```

Any one of those conditions being false — npm < 12, an existing `allowScripts` block, or no `npm install` in CI — passes with a one-line reason. To fix a failing check, run `allow --write`: it writes the auto-approved entries and leaves the `_review` packages out (writing them would be deciding for you — they stay pending until a human looks).

## Governance policy

By default `allow`/`review`/`sync` auto-approve SAFE/LOW behavioral risk. A `script-lens.policy.json` in the project root (or `--policy <file>`) turns that fixed heuristic into a team decision:

```json
{
  "autoApprove": {
    "maxRisk": "LOW",            // approve up to this risk (SAFE|LOW|MEDIUM|HIGH)
    "denyCapabilities": ["net"], // never auto-approve a script that reaches the network…
    "minAgeDays": 30,            // …or a version published < 30 days ago (needs trust data)
    "requireProvenance": false   // …or one without sigstore provenance
  },
  "waivers": {
    "sharp": { "allow": true, "reason": "vetted native build", "expires": "2027-01-01" }
  }
}
```

Waivers are explicit human decisions that override the heuristic until they expire — an auditable record of *why* a risky package was trusted. With no policy file present, behavior is exactly the built-in default.

## Keeping the allowlist alive — in any package manager

Version-pinned npm entries are silently invalidated by every dependency bump; name-keyed managers (pnpm/yarn/bun) drift as packages come and go. `sync` reconciles your manager's native allowlist with the lockfile — auto-detected, written in the right format:

```bash
npx npm-script-lens sync --check     # CI: exit 1 when the allowlist drifted
npx npm-script-lens sync --write     # drop stale entries, add new scripted packages,
                                     # (npm) re-pin upgrades — PRESERVING decisions when
                                     # the new version gained no capabilities
npx npm-script-lens review --output-allowscripts  # review pending WITH script content, then write
npx npm-script-lens approve          # step through risky packages interactively (npm)
```

## One-command adoption

```bash
npx npm-script-lens init             # scaffold script-lens.policy.json + a CI workflow
```

`init` writes a starter policy and a ready-to-commit GitHub Action (audit + `allow --ci-check` gate), skipping anything that already exists (`--force` to overwrite). Add `--auto-fix` for a Renovate/Dependabot bot workflow, or `--hook` to install a git pre-commit hook that runs `sync --check`. Prefer the [pre-commit framework](https://pre-commit.com)? This repo ships a [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml).

## npm v12 approve-scripts bug check

npm v12's own tooling has two known bugs that leave teams with a green `approve-scripts` run and a red `npm ci`:

- **Optional dependency gap** ([npm/cli#9562](https://github.com/npm/cli/issues/9562)): `npm approve-scripts --allow-scripts-pending` never lists optional dependencies — but `npm ci --strict-allow-scripts` still rejects any optional dep with install scripts that is missing from `allowScripts`. The classic trap is `fsevents`: it only *installs* on macOS, so on a Linux CI runner nothing surfaces it, and strict mode fails the build anyway.
- **EGLOBAL in global installs** ([npm/cli#9463](https://github.com/npm/cli/issues/9463)): when `npm install -g <pkg>` warns about unreviewed install scripts, the suggested `npm approve-scripts` command errors with `EGLOBAL` — there is no post-install approval path in global contexts. The working form is allowing at install time: `npm install -g --allow-scripts=<pkg> <pkg>`.

```bash
npx npm-script-lens audit --check-v12-gaps            # markdown report
npx npm-script-lens audit --check-v12-gaps --json     # { findings: [...] }
npx npm-script-lens audit --check-v12-gaps --sarif v12.sarif
```

The first check reads `optional` + `hasInstallScript` from your `package-lock.json`, resolves the actual script names from registry metadata, and flags every optional dep with install scripts that your `allowScripts` block doesn't cover (bare-name and version-pinned keys both count as decisions). The second scans `.github/workflows/*.yml` for `npm install -g` / `npm i -g` lines, checks each installed package's registry metadata for install scripts, and flags the ones without an `--allow-scripts` guard — anchored to the exact workflow file and line. Findings are severity `warn` and never fail the run; packages the registry can't confirm are skipped rather than guessed (except when the lockfile itself says `hasInstallScript`, which is trusted even if the registry is unreachable).

In the [GitHub Action](#github-action) this runs as a separate step controlled by `check-v12-gaps` (default `auto`: runs only when the runner's npm is v12+). It writes to the job summary, emits `::warning` annotations, and merges its findings into the SARIF file from the main audit step so code scanning shows them too.

## Committed audit manifest

The strongest review signal is a diff a human already reads: the PR diff itself. `manifest` writes a **stable, minimal receipt of install-time behavior** — sorted `name@version` → capability kinds — that you commit next to your lockfile. When a dependency change alters what install scripts *can do*, the git diff of that file **is** the approval-surface change, reviewable with zero tooling:

```bash
npx npm-script-lens manifest --write     # writes script-lens.json next to the lockfile
npx npm-script-lens manifest --check     # CI: exit 1 if behavior drifted from the committed file
```

```json
{
  "tool": "npm-script-lens",
  "version": "0.4.0",
  "packages": {
    "sharp@0.33.5": { "risk": "HIGH", "capabilities": ["env", "exec", "obf"] }
  }
}
```

It records *behavior only* — no download counts, publish age, or OSV status — so the file changes when a package's capabilities change, not when its popularity does (live malware/trust checks stay in `audit`). A bump in the `version` field means the detector itself changed and results are worth re-reviewing. In the Action, set `manifest-check: 'true'` to fail PRs that leave the manifest stale, with the drift written to the job summary. _(Requested by [@raju_dandigam](https://dev.to/booyaka101/npm-v12-stopped-running-install-scripts-which-ones-do-you-approve-a-real-audit-walkthrough-b1l#comments) — thanks!)_

## MCP server (for AI agents)

```bash
npx npm-script-lens mcp
```

Runs an MCP stdio server with three tools: `audit_package` (audit one package — before an agent adds it as a dependency), `audit_lockfile`, and `classify_allowscripts` (audit a lockfile and return the `allow` split — `{allowScripts, _review}` — so an agent can generate the block non-interactively). Claude Code config:

```json
{ "mcpServers": { "npm-script-lens": { "command": "npx", "args": ["npm-script-lens", "mcp"] } } }
```

Real output for a project depending on `sharp`, `prisma`, `core-js`, `chalk` (39 locked packages, ~5s): see [`fixtures/demo-report.md`](fixtures/demo-report.md). Highlights:

| package | script | risk | signals |
|---|---|---|---|
| `sharp@0.33.5` <br>_1.9y old · 74M dl/wk · 1 maintainer_ | install | 🔴 HIGH | `exec: node-gyp rebuild --directory=src` · `exec: require('child_process')` … |
| `@prisma/engines@5.22.0` <br>_via prisma · 15M dl/wk · provenance ✓_ | postinstall | 🔴 HIGH | `net: require('@prisma/fetch-engine')` · `exec: require('execa')` · `fs: writeFileSync` … |
| `core-js@3.38.1` | postinstall | 🟡 LOW | `fs: fs.writeFileSync` · `env: process.env` |
| `chalk@5.3.0` | — | 🟢 SAFE | no lifecycle scripts |

```json
{
  "allowScripts": {
    "@prisma/engines@5.22.0": false,
    "core-js@3.38.1": true,
    "prisma@5.22.0": true,
    "sharp@0.33.5": false
  }
}
```

## GitHub Action

```yaml
name: audit-install-scripts
on: pull_request
permissions:
  pull-requests: write
jobs:
  lens:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Booyaka101/npm-script-lens@v1
        with:
          path: '.'               # dir or lockfile; npm/yarn/pnpm auto-detected
          fail-on-high: 'true'    # exit 1 when a HIGH-risk script appears
          comment-on-pr: 'true'   # post the report as a PR comment
```

The action writes the report to the job summary, comments on the PR (plain GitHub REST `issues/comments` call using `GITHUB_TOKEN` — same endpoint octokit uses), and fails the job when `fail-on-high` is true and a HIGH package exists.

Optional inputs: `diff-base` (audit only packages added/upgraded vs a base lockfile, e.g. one extracted from the PR base branch), `check-v12-gaps` (`auto`/`true`/`false` — the [npm v12 approve-scripts bug check](#npm-v12-approve-scripts-bug-check), auto-enabled when the runner's npm is v12+), `ci-check` (`'true'` to enable — the [allow --ci-check](#ci-guard) gate as a fail-fast Action step: fails the job when the runner's npm is v12+, a workflow runs `npm install`, and `package.json` has no `allowScripts` block, before the missing block silently breaks a downstream install), `sync-check` (`'true'` — fails the job when the install-script allowlist has drifted from the lockfile; cross-ecosystem, auto-detects npm/pnpm/yarn/bun), and `sarif-file` for code scanning alerts:

```yaml
      - uses: Booyaka101/npm-script-lens@v1
        with:
          sarif-file: lens.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: lens.sarif
```

## Run from source

```bash
npm install --ignore-scripts
node src/cli.js audit --path fixtures/demo --fail-on-high
npm test        # analyzer/lockfile/reporter units, offline mock-registry tests,
                # live acceptance against the real registry, and a full action
                # dry-run against a local mock GitHub API
```

Node.js ≥ 20 (uses global `fetch`). No paid APIs — the public npm registry, plus the free OSV.dev and npm downloads APIs for trust enrichment (`--no-trust` or `--offline` to skip).

## Staying current with npm

This tool's value is coupled to npm's own behavior — the `allowScripts` field, the `unreviewedScripts` shape in `npm install --dry-run --json`, the approve-scripts commands. Those will drift across npm releases, so npm-script-lens is built to notice when they do rather than fail silently:

```bash
npx npm-script-lens doctor          # does this build still understand your npm?
npx npm-script-lens doctor --json   # machine-readable, for scripts/CI
```

`doctor` probes your local npm and reports each contract assumption — version, allowScripts enforcement, a parser self-test, a live dry-run shape check, and each npm-bug detector's upstream status — then **exits 1 on genuine drift** (an npm output shape this build no longer recognizes). Under the hood:

- Every npm coupling lives in one file (`src/npm-contract.js`) — a future npm change is a one-line patch, not a hunt.
- `review` **warns loudly and falls back** instead of silently trusting an unfamiliar npm answer as "nothing pending".
- A scheduled **npm-compat canary** (`.github/workflows/npm-compat.yml`) drives the *real* npm across `12`/`latest`/`next` on a matrix and goes red on drift — the tripwire the unit tests (which use stub npms) can't be.
- The two npm-v12 approve-scripts bug detectors are **version-aware**: the report says which npm it checked and links each bug's upstream status, so a detector can't quietly outlive the bug it was written for.

## Exit codes

| code | meaning |
|---|---|
| `0` | success (or findings that are warn-level only, e.g. `audit --check-v12-gaps`) |
| `1` | an actionable failure: `audit --fail-on-high` found HIGH/malicious · `sync --check`/`manifest --check` drift · `allow --ci-check` would break on npm v12 · `doctor` detected npm drift · `diff` found an added/modified install script |
| `2` | a usage/runtime error (bad ref, missing lockfile, unreadable input) |

## Commands at a glance

| command | does |
|---|---|
| `audit` | scan a lockfile, report install-script risk (Markdown/JSON/SARIF); `--fail-on-high`, `--diff`/`--since`, `--check-v12-gaps` |
| `allow` | split scripted packages into an auto-approved allowlist + `_review`, in your manager's native format; `--write`, `--ci-check`, `--manager`, `--policy` |
| `review` | show pending approvals **with the actual script content** + verdict; `--output-allowscripts` writes decisions |
| `diff` | compare a package's install scripts (+ implicit node-gyp) across two versions; exit 1 on any add/modify; `--json` |
| `sync` | reconcile the native allowlist with the lockfile (drop stale, add new); `--check` for CI |
| `doctor` | is this build still in sync with your npm? contract probe + drift alarm |
| `init` | scaffold policy + CI workflow (`--auto-fix` bot, `--hook` git pre-commit) |
| `manifest` | committable behavior receipt whose git diff is the approval-surface change |
| `completion` | print a shell completion script (bash / zsh / fish) |
| `mcp` | MCP server for AI agents (`audit_package`, `audit_lockfile`, `classify_allowscripts`) |

## How it compares

The install-script-allowlist space has good tools — but each covers one slice:

| | behavioral risk analysis | npm | pnpm | yarn | bun | writes native allowlist | policy / waivers | CI drift gate | MCP |
|---|---|---|---|---|---|---|---|---|---|
| **npm-script-lens** | ✅ exec/net/fs/obf + OSV + trust | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `@lavamoat/allow-scripts` | ❌ (allowlist mgmt only) | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | partial | ❌ |
| `can-i-ignore-scripts` | ❌ (lists scripts) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| native `npm approve-scripts` / `pnpm approve-builds` / `bun pm trust` | ❌ | one each | | | | ✅ | ❌ | ❌ | ❌ |

The combination — **behavioral evidence** for the decision, in **every manager's** native format, with **policy** and **CI enforcement** — is what makes it the one tool to standardize on.

## Honest limitations

- **Static capability detection, not proof of malice.** A HIGH score means "this script *can* spawn processes" — exactly the question to answer before approving, but plenty of HIGH packages (native builds) are legitimate. The lens gives evidence; you make the call. Only sandboxed execution could say more, and running untrusted install scripts to observe them is deliberately out of scope.
- Scripts invoking **binaries from other packages** (`husky install`, `patch-package`) are resolved when a lockfile package with the same name owns the bin: that package's actual bin script is fetched, analyzed, and the row is **re-scored on real evidence** (`bin: husky install → husky@9.1.7` + what the script actually does). Bins with no same-name owner in the lockfile stay conservatively HIGH as `exec: … (unresolved binary)`.
- **Helper dependencies**: capability hidden inside helpers is caught via a curated list (`axios`, `got`, `undici`, `@prisma/fetch-engine`, …) plus `--deep`, which follows bare `require()`s from install-script code into the matching lockfile package's entry file (one level). A helper outside the lockfile, or loaded indirectly, can still slip a tier.
- **Obfuscation**: `eval`/`new Function`/`vm` and string-built `require()`s score HIGH, and base64/char-code **literal** payloads are **decoded and re-analyzed** — the report shows what the hidden code actually does, not just that it hides. Payloads assembled only at runtime (downloaded, decrypted, env-derived) remain opaque: flagged, not decoded. Plain variable indirection (`require(someVar)`) is deliberately not flagged — it's ubiquitous in bundler output.

## Get it

- **CLI**: `npx npm-script-lens audit` — [npmjs.com/package/npm-script-lens](https://www.npmjs.com/package/npm-script-lens)
- **GitHub Action**: `uses: Booyaka101/npm-script-lens@v1` — [releases](https://github.com/Booyaka101/npm-script-lens/releases)
- **VS Code extension**: inline install-script risk in `package.json` — [`editors/vscode`](editors/vscode)
- **Neovim plugin**: `vim.diagnostic` on `package.json` — [`editors/nvim`](editors/nvim)
- **MCP server** for AI agents: `npx npm-script-lens mcp`
- **Pre-commit**: [`init --hook`](#one-command-adoption) or the [pre-commit framework](.pre-commit-hooks.yaml) · **HTML report**: `audit --html report.html`
- Join the conversation: [npm/rfcs#897](https://github.com/npm/rfcs/issues/897) (allowScripts review-report RRFC) · [npm v12 migration discussion](https://github.com/community/community/discussions/198547)
