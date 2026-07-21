# npm-script-lens

**Know what an install script actually does before you approve it.**

Since [npm v12 (July 8, 2026)](https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/), dependency lifecycle scripts (`preinstall`, `install`, `postinstall`) and implicit `node-gyp` builds **no longer run unless explicitly allowed** via the `allowScripts` field in `package.json`. That leaves every team staring at a list of package names asking: *which of these are safe to approve?*

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
# --diff BASE   audit only packages added/upgraded vs a base lockfile
# --offline     analyze node_modules on disk instead of the registry
# --no-trust    skip OSV/downloads/provenance enrichment
# --no-cache    disable the on-disk result cache
# --fail-on-high  exit 1 if any package scores HIGH or is known malicious
```

Reviewing a PR? Audit only what changed — and see what **upgrades gained**:

```bash
git show origin/main:package-lock.json > /tmp/base-lock.json
npx npm-script-lens audit --diff /tmp/base-lock.json --fail-on-high
```

In diff mode, a package that was already in the tree but changed version is compared against the base version's analysis: `**⚠️ gained vs 1.2.0:** net: fetch()` is the fingerprint of a hijacked release (event-stream, the 2025 Shai-Hulud wave); `no new capabilities vs 1.2.0` is a boring upgrade.

## Keeping allowScripts alive

npm v12 entries are version-pinned, so every dependency bump silently invalidates approvals. Two commands make this a workflow instead of a one-shot:

```bash
npx npm-script-lens sync --check     # CI: exit 1 when allowScripts drifted
npx npm-script-lens sync --write     # update package.json: drop stale entries,
                                     # re-pin upgrades (decisions are PRESERVED when
                                     # the new version gained no capabilities,
                                     # flagged for re-review when it did), add new
npx npm-script-lens approve          # step through risky packages interactively:
                                     # evidence per package, y/n, written to package.json
```

## MCP server (for AI agents)

```bash
npx npm-script-lens mcp
```

Runs an MCP stdio server with two tools: `audit_package` (audit one package — before an agent adds it as a dependency) and `audit_lockfile`. Claude Code config:

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

Optional inputs: `diff-base` (audit only packages added/upgraded vs a base lockfile, e.g. one extracted from the PR base branch) and `sarif-file` for code scanning alerts:

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

## Honest limitations

- **Static analysis**: capability detection, not proof of malice. A HIGH score means "this script *can* spawn processes," which is exactly what you want to know before approving it — but plenty of HIGH packages (native builds) are legitimate. The lens gives evidence; you make the call.
- Scripts invoking **binaries from other packages** (`husky install`, `patch-package`) are conservatively flagged HIGH as `exec: … (unresolved binary)` — their code lives in a different tarball.
- Network capability hidden inside **helper dependencies** is caught via a curated capability list (`node-fetch`, `axios`, `got`, `undici`, `@prisma/fetch-engine`, …); a helper not on the list can slip to a lower tier. Notably, real-world MEDIUM (network *without* exec) is rare — installers that download almost always also spawn or chmod, and exec dominates the score.
- **Obfuscation is flagged, not decoded**: `eval`/`new Function`/`vm`, string-built `require()` specifiers, and base64/char-code payload decoding all score HIGH with an `obf:` signal — but the lens reports *that* code hides itself, it doesn't reconstruct what the hidden code does. A `require(someVariable)` behind plain variable indirection (ubiquitous in bundler output and native-binding loaders) is deliberately not flagged.

## Distribution

**First step: `npm publish` — the name `npm-script-lens` is unclaimed (verified 404 on the registry, 2026-07-21).** Then push to GitHub and tag `v1` so the Action is usable, and post the CLI + sample report in the npm v12 migration threads ([npm/rfcs#897](https://github.com/npm/rfcs/pull/897) and the GitHub community discussion on install-script opt-in), where people are asking for exactly this review evidence.
