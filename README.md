# npm-script-lens

**Know what an install script actually does before you approve it.**

_The install-script-approval tool for **npm · pnpm · yarn · bun** — from your **CLI**, **CI**, **editor**, and **AI agent**._

Since [npm v12 (July 8, 2026)](https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/), dependency lifecycle scripts (`preinstall`, `install`, `postinstall`) and implicit `node-gyp` builds **no longer run unless explicitly allowed** via the `allowScripts` field in `package.json` — and [git and remote-URL dependencies **no longer resolve at all**](#git-and-remote-dependencies-the-other-two-npm-v12-flips) unless opted in via `allow-git`/`allow-remote`. And npm isn't alone — **pnpm** (`allowBuilds`), **yarn** Berry (`dependenciesMeta.built`), and **bun** (`trustedDependencies`) all made install scripts opt-in too. That leaves every team, on every package manager, staring at a list of package names asking: *which of these are safe to approve?*

`npm-script-lens` answers that with evidence, not vibes — the review-report mode the community asked for in [npm/rfcs#897](https://github.com/npm/rfcs/pull/897). For every package in your lockfile — `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and berry), `pnpm-lock.yaml`, or `bun.lock` — it:

1. fetches the version metadata from the public npm registry,
2. stream-downloads the tarball and indexes its source files (`tar-stream`, nothing written to disk) — skipped entirely for the majority of packages with no install-time scripts, which is why real audits take seconds,
3. statically analyzes each `preinstall`/`install`/`postinstall` script with `acorn` — including the JS the script actually runs: `node <file>` targets, `node -e` eval bodies, relative `require()`/`import` chains, `path.join(__dirname, …)` indirections, and `npm run <target>` recursion into the package's own scripts (3 levels deep, cycle-safe). Packages that ship a root `binding.gyp` with no install script get their **implicit `node-gyp rebuild`** surfaced too — npm v12 blocks those builds as well. (`prepare` is deliberately excluded: npm never runs it for registry-installed deps, and flagging leftover `"prepare": "husky install"` lines would be noise.)
4. **reads inside `binding.gyp`** (and the `.gypi`/`.gyp` files it includes) for native packages — see [the gyp lens](#the-gyp-lens-what-is-actually-inside-bindinggyp) — because gyp *runs* the commands in that file at configure time,
5. scores the behavior and emits a Markdown report plus a **ready-to-paste, version-pinned `allowScripts` block**,
6. adds context to every risky package: **how it entered your tree** (`via prisma → @prisma/engines`), **whether OSV lists it as malicious** (⛔ hard flag, always denied), and **publisher trust signals** — publish age, weekly downloads, maintainer count, sigstore provenance — so "🔴 HIGH, 74M dl/wk, 10 years old" reads differently from "🔴 HIGH, published 4 days ago, 12 dl/wk".

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
# --cooldown [h]  exit 1 if any locked version is younger than N hours (default 72)
# --cooldown-allow PKG...  exempt from --cooldown, by name or name@version
```

Reviewing a PR? Audit only what changed — and see what **upgrades gained**:

```bash
npx npm-script-lens audit --since origin/main --fail-on-high   # base lockfile pulled from the ref for you
# …or point --diff at a base lockfile you extracted yourself:
git show origin/main:package-lock.json > /tmp/base-lock.json
npx npm-script-lens audit --diff /tmp/base-lock.json --fail-on-high
```

In diff mode, a package that was already in the tree but changed version is compared against the base version's analysis: `**⚠️ gained vs 1.2.0:** net: fetch()` is the fingerprint of a hijacked release (event-stream, the 2025 Shai-Hulud wave); `no new capabilities vs 1.2.0` is a boring upgrade.

## The gyp lens: what is actually inside `binding.gyp`?

`npm-script-lens` is the only install-script allowlist/approval tool that reads
**inside** `binding.gyp` and `.gypi` — and the only one that **diffs them
between versions**.

Every such tool (including this one, before v1.3.0) treated `binding.gyp` as a
flag: present ⇒ "implicit `node-gyp rebuild`". But gyp *evaluates* that file
before a line of C is compiled, and executes the commands in it —
[`subprocess.run(contents, stdout=PIPE, shell=use_shell, …)`](https://github.com/nodejs/gyp-next/blob/main/pylib/gyp/input.py)
in gyp-next. So the build file is a place to put install-time code where
approval tooling was not looking. That is what the June 2026 campaign used —
[ReversingLabs, 2026-06-04](https://www.reversinglabs.com/blog/npm-bindinggyp-cicd-secrets)
(286 malicious versions across 56 packages), whose payload was a single line:

```json
{"targets":[{"target_name":"Setup","type":"none","sources":["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]}]}
```

[Aikido's 2026-06-09 teardown](https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system)
enumerates the channels; `npm-script-lens` covers all of them:

| Channel | What it does |
|---|---|
| `<!(` `<!@(` | command expansion — gyp runs it in a shell and substitutes the output |
| `>!(` `>!@(` `^!(` `^!@(` | the same thing in gyp's *late* and *latelate* phases — one character apart from `<!(`, and invisible to a naive scan |
| `<!pymod_do_main(` (+ `>`/`^`) | imports a Python module and calls its `DoMain()` |
| `<\|(` `>\|(` `^\|(` | listfile expansion |
| `actions[].action` · `rules[].action` · `postbuilds[].action` | explicit build steps that run commands |
| `make_global_settings` | replaces `CC`/`CXX`/`LINK` — a compiler hijack |
| `conditions` | flagged when the condition string reaches for the Python-eval sandbox escape (`__class__`, `__subclasses__`, `__import__`, `__builtins__`) |

Plain `<(var)` / `<@(var)` interpolation is **never** flagged — real files mix
both, and `bufferutil`'s `<!(cc -v …)` sitting next to its `<(clang_version)`
is a committed regression test.

`review` prints what will run above the file itself. Real output for
`better-sqlite3@11.10.0` — note the findings come from `deps/sqlite3.gyp`, a
file the parent `binding.gyp` only *references*:

```
── better-sqlite3@11.10.0  [🔴 HIGH]
   deps/sqlite3.gyp:28  actions[].action build action → node copy.js <(SHARED_INTERMEDIATE_DIR)/sqlite3
   deps/sqlite3.gyp:41  actions[].action build action → node copy.js <(SHARED_INTERMEDIATE_DIR)/sqlite3 <(sqlite3)
   ┌─ binding.gyp (39 lines)
   │   1  # ===
   │   2  # This is the main GYP file, which builds better-sqlite3 with SQLite itself.
   …
```

In `audit`, these become `gyp:` signals that score **HIGH** (a shell command at
install time is a shell command), appear in `--sarif` under the rule
`gyp-exec-channel`, and can be banned outright via a policy's
`denyCapabilities: ["gyp"]`.

> **Upgrading from ≤ 1.2.0?** A `manifest --check` baseline containing native
> packages may now show a new `gyp` capability — the tool sees something it
> previously could not. Re-baseline once with `manifest --write` and commit it.

## diff: what did an upgrade change in the install scripts?

Before you bump a pin, see exactly which install-time behavior a new version adds or changes — the surface npm v12 will ask you to re-approve. `diff` compares the `preinstall`/`install`/`postinstall` scripts (and the implicit `node-gyp rebuild` that ships with a root `binding.gyp`) between two versions, straight from the registry:

```bash
npx npm-script-lens diff sharp@0.32.6 sharp@0.33.0
# --json   emit { unchanged, added, removed, modified, gyp } instead of colored text
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

`binding.gyp` is compared **by content, not by existence** (fixed in 1.3.0). A
version that keeps its build file but *rewrites* it changes what runs at
install time, and used to slip through as `UNCHANGED` / exit 0 — the shape the
June 2026 wave-2 releases had. Now:

```
$ npx npm-script-lens diff bufferutil@4.0.8 bufferutil@4.0.9
bufferutil@4.0.8 → bufferutil@4.0.9
UNCHANGED: install
MODIFIED: binding.gyp (implicit node-gyp rebuild — contents changed)
      {
    +   'variables': {
    +     'openssl_fips': ''
    +   },
        'targets': [
…
$ echo $?
1
```

`--json` carries `{ gyp: { changed, gainedChannels } }`; `gainedChannels` lists
gyp execution channels present in the new version and absent from the old (here
it is empty — a benign build-file edit, no new way to run a command).

Exit `0` when everything is unchanged; exit `1` the moment any script is **added or modified** — so a Renovate/Dependabot CI step can fail the moment an upgrade grows its install-time surface. (A pure removal stays exit `0`.)

## git and remote dependencies: the other two npm v12 flips

npm v12 doesn't just gate install *scripts* — it also stops resolving **git
dependencies** (`github:user/repo`, `git+ssh://…`) and **remote tarball URLs**
(`https://…/pkg.tgz`) unless you opt in via `allow-git` / `allow-remote` in
`.npmrc`. Both are the strict enum `all` | `none` | `root` (default `none`);
`root` allows only deps declared in your **root** package.json, so a single
*transitive* git dep forces `all`. There's no migration tooling upstream — the
[official discussion](https://github.com/orgs/community/discussions/198547)'s
best offer is `grep -r 'git+' package.json`. `sources` does the whole job:

```bash
npx npm-script-lens sources                # report + the minimal correct .npmrc
npx npm-script-lens sources --check        # CI: exit 1 on insufficient, over-permissive, or invalid config
npx npm-script-lens sources --write        # merge the minimal values into .npmrc (comment-preserving)
npx npm-script-lens sources --json         # { git, remote, npmrc }
```

Real output for a project with a root-declared git dep and a transitive one:

```
git dependencies (2)
  ROOT        left-pad @ github:left-pad/left-pad
  TRANSITIVE  some-pkg @ git+ssh://git@github.com/a/b.git   via my-lib -> some-pkg
remote dependencies (0)

minimal correct .npmrc:
  allow-git=all

allow-git=all is required because 1 git dependency is transitive; allow-git=root would otherwise suffice.
Re-point or drop `some-pkg` (via my-lib) to tighten this to allow-git=root.
```

It reads all four lockfile dialects (package-lock v1/v2/v3, yarn classic +
berry, pnpm, bun.lock) with **zero network calls**, and `--check` fails in
three *distinct* ways so CI tells you what to do:

- **insufficient** — npm v12 will refuse the install (missing `.npmrc`, or
  `root` committed while a transitive git dep exists);
- **over-permissive** — `all` committed where `root` (or nothing) suffices:
  the least-privilege ratchet;
- **invalid** — `allow-git=true` or a bare `--allow-git`, which several
  published migration guides recommend, is **not in the enum**: npm treats it
  as unset and your install still breaks. The check names the valid three.

`allow --ci-check` folds the insufficient/invalid cases into its fast CI gate
too, and `doctor` reports whether your npm has the keys at all (they appeared
in 11.10.0 / 11.15.0) and warns that `allow-git=root` is unreliable on npm 11
([npm/cli#9189](https://github.com/npm/cli/issues/9189), closed via PR #9206 —
root-level git deps were wrongly rejected): prefer `all` there. The `.npmrc`
emitter is npm-only; for yarn/pnpm/bun lockfiles the dependency report still
works, the write is skipped with a note.

## cooldown: don't be the first to install a version

Every other check here asks *what does this package do?*. Cooldown asks only
*how old is this version?*

On 2026-08-04 attackers compromised the `keyv` maintainer's GitHub account
(~127M weekly downloads) and pushed the Mini Shai-Hulud worm into `keyv`,
`cacheable`, `flat-cache` and `file-entry-cache`. It spread to nine unrelated
organisations in about half an hour and 400+ packages that day — and, like
every worm before it, was identified and unpublished within hours. The install
that hurts you is the one that lands inside that window.

So don't go first.

```bash
# fail the build if any locked version is younger than 72h (the default)
npm-script-lens audit --cooldown

# stricter, or looser
npm-script-lens audit --cooldown 24

# ship a genuine same-day fix anyway
npm-script-lens audit --cooldown --cooldown-allow hotfix-pkg@2.0.1
```

```
✗ cooldown 72h — 1 package version(s) published too recently:
  keyv@5.5.5  6.0h old  (clears 2026-08-07 14:00Z)

These may be perfectly fine. Cooldown does not inspect them — it declines to be
among the first to install a version, because npm worms are typically caught
within hours. Wait, pin to an older version, or exempt with --cooldown-allow.
```

Notes:

- It is **opt-in**. Without the flag, nothing changes.
- Age comes from the absolute publish timestamp at evaluation time, never from
  a cached day-resolution age — a stale cache errs toward *older*, which would
  fail open on precisely the young version this is meant to catch.
- Packages with no publish date (`--offline`, private registries) are listed as
  unchecked rather than blocked.
- Because a poisoned version doesn't need a lifecycle hook to hurt you,
  `--cooldown` fetches publish dates for **every** locked package, not just the
  ones with install scripts. That is more registry traffic than a plain audit.

## publish: will your release workflow survive January 2027?

The other side of the same coin: npm-script-lens guards the *install* side of
your workflows; `publish` guards the *publish* side. The [GitHub changelog of
2026-07-31](https://github.blog/changelog/2026-07-31-restricting-npm-bypass-2fa-granular-access-tokens/)
is explicit: *"2FA-bypass tokens will also lose direct publish. Their
publishing surface will reduce to reading private packages and staging a
publish, which a maintainer approves with 2FA. We are targeting January 2027
for this update."* Phase 1 already shipped on 2026-07-31, so publishing is the
last thing those tokens can still do. If your release workflow does
`npm publish` with `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}`, it has an
expiry date.

```bash
npx npm-script-lens publish            # classify every CI publish path + the migration patch
npx npm-script-lens publish --check    # CI: exit 1 when a path uses a long-lived token or is BROKEN
npx npm-script-lens publish --json     # { cliff, floors, counts, paths, repo, engines }
npx npm-script-lens publish --sarif f  # rules publish-token-cliff + publish-oidc-broken, workflow-line anchored
```

It reads `.github/workflows/*.yml`, `.github/actions/**/action.yml`,
`.gitlab-ci.yml` and `.circleci/config.yml` (no network, no YAML dependency),
finds `npm publish`, `npm stage publish`, `pnpm publish`, `yarn npm publish`,
`np`, `semantic-release`, `changesets/action` and `JS-DevTools/npm-publish`,
and classifies each path as exactly one of:

- **TRUSTED**: an id-token grant (`permissions: id-token: write` or
  `write-all`; GitLab `id_tokens` with audience `npm:registry.npmjs.org`;
  CircleCI `NPM_ID_TOKEN`) and no token: already on [trusted publishing
  (OIDC)](https://docs.npmjs.com/trusted-publishers), survives the cliff;
- **STAGED**: `npm stage publish`, where a maintainer approves with 2FA
  (`npm stage approve <stage-id>`), survives the cliff;
- **TOKEN**: `NODE_AUTH_TOKEN`/`NPM_TOKEN` in the env, or an `.npmrc` write
  containing `_authToken`. **Stops working around January 2027**, and fails
  `--check`;
- **BROKEN**: trusted publishing is granted, but the job's
  `actions/setup-node` is v6 or older *and* passes
  `registry-url: https://registry.npmjs.org`. Every setup-node release up to
  v6 answers that input by writing
  `//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}` into an `.npmrc` and
  exporting a dummy `NODE_AUTH_TOKEN`, so npm sees auth as configured and
  never starts the OIDC exchange, so the publish fails with ENEEDAUTH/E404
  ([npm/documentation#1960](https://github.com/npm/documentation/issues/1960);
  fixed in
  [setup-node v7.0.0](https://github.com/actions/setup-node/releases/tag/v7.0.0)).
  The official trusted-publishers docs still show the broken `@v6` recipe.
  Fails `--check`; the report gives all three fixes (bump to `@v7`, drop
  `registry-url:`, or `sed -i '/_authToken/d' "$NPM_CONFIG_USERCONFIG"`) and a
  job that already strips the line stays TRUSTED. An unresolvable setup-node
  ref (SHA pin, branch, expression) gets a ⚠️ note, never a downgrade;
- **UNKNOWN**: a publish exists but the auth is ambiguous (third-party
  reusable workflows, both grant and token, neither visible): reported, never
  a failure.

A publish step hidden behind `uses: ./.github/actions/release` is followed
into the composite action itself (and into local reusable workflows, nested up
to 3 levels): the path anchors to the real `action.yml` line, an indented
`via .github/workflows/release.yml:11 (job release, step "Release")` line
shows the call chain, and the auth threads the way GitHub threads it:
composite actions cannot declare `permissions`, so the id-token grant is
always the calling job's, and a composite
`env: NODE_AUTH_TOKEN: ${{ inputs.npm-token }}` is resolved through the
calling step's `with:` map back to `secrets.NPM_TOKEN`. A publishing composite
under `.github/actions/` that no workflow in the repo references is still
reported (UNKNOWN, since it may be called from another repo). Third-party actions
(`actions/checkout@v4`) are never flagged.

Then it does the three checks no migration blog performs:

1. **Version floors**, verbatim from docs.npmjs.com: trusted publishing
   *"requires npm CLI version 11.5.1 or later and Node version 22.14.0 or
   higher"*; staged publishing *"requires npm CLI version 11.15.0 or later and
   Node version 22.14.0 or higher."* A `setup-node` pin (or an
   `engines.node` minimum) below the floor is called out with exactly which
   fix it blocks. Migrating a workflow that's pinned to Node 20 fails at the
   first publish, so the pin bump is part of the fix.
2. **Runner eligibility.** Trusted publishing supports **only** GitHub-hosted
   runners, GitLab.com shared runners and CircleCI cloud: *"Self-hosted
   runners are not currently supported but are planned for future releases."*
   A `runs-on: self-hosted` publish job gets trusted publishing marked
   **UNAVAILABLE** and is routed to the one path that survives there:
   `npm stage publish` + `npm stage approve <stage-id>`.
3. **The npmjs.com side, pre-filled.** Trusted publishing also needs config on
   npmjs.com; `publish` emits the settings checklist filled in from your repo
   (org/user, repository, workflow filename *with its extension*, the
   environment name if the job declares one, and the allowed actions).

Real output for a workflow publishing with a token on Node 20:

```
publish paths (1)
  TOKEN     .github/workflows/release.yml:15  npm publish   [job release · ubuntu-latest]
            long-lived token: NODE_AUTH_TOKEN in the publish step env (line 17)

⛔ 1 TOKEN publish path. Direct token publishing stops working around January 2027.

fix for .github/workflows/release.yml:15, switch to trusted publishing (OIDC):
  add to the `release` job (or the workflow top level) in .github/workflows/release.yml:
    + permissions:
    +   id-token: write
  remove the token from the publish step (line 17):
    - env:
    -   NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
  ⚠️  node-version 20 (.github/workflows/release.yml:12) is below the Node 22.14.0 floor …

npmjs.com trusted-publisher settings (package Settings → Trusted publisher):
  GitHub organization or user: acme
  repository:                  widget
  workflow filename:           release.yml   (with its extension, exactly as on disk)
  environment:                 (the job declares none, leave blank)
  allowed actions:             npm publish   (also allow "npm stage publish" if you plan to stage releases)
```

`doctor` reports the same readiness mix (naming the setup-node ref on a
BROKEN path), and the GitHub Action's [`publish-check` input](#github-action)
fails the job with an `::error` and a `publish-token-cliff` /
`publish-oidc-broken` SARIF result when a TOKEN or BROKEN path remains.

## hooks: what runs when the folder is *opened*?

npm-script-lens covers three moments where code runs without you asking:
install time (`audit`/`allow`), resolution time (`sources`), publish time
(`publish`). The 2026-08-04 keyv/ChainDrop worm used a fourth — **open
time**. [Wiz's teardown](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack)
says it plainly: *"Persistence is attempted via Claude Code hooks and VS Code
`tasks.json`"* — two separately-hashed `setup.mjs` payloads, one under
`.claude`, one under `.vscode`. And the tarball half predates the worm:
[hijacked npm packages](https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html)
`html-to-gutenberg` and `fetch-page-assets` (2026-05-25) shipped a hidden VS
Code task named `eslint-check` with `"runOn": "folderOpen"` — firing when the
package directory itself is opened as a workspace.

```bash
npx npm-script-lens hooks                  # scan the working tree (monorepo subdirs included)
npx npm-script-lens hooks --check          # CI: exit 1 at or above the --fail-on floor (default high)
npx npm-script-lens hooks --deps           # also scan every locked dependency's tarball
npx npm-script-lens hooks --json           # { findings, partial, caveats, deps }
npx npm-script-lens hooks --sarif hooks.sarif   # rule hook-auto-run, anchored to the real file:line
```

Two surfaces (one table row each in `src/hooks.js` — adding an editor is a
one-file patch):

- **`.vscode/tasks.json`** — any task whose `runOptions.runOn` is
  `"folderOpen"`, with its label, command+args, type, and whether
  `presentation.reveal: "silent"` hides the terminal.
- **`.claude/settings.json`** — a [documented project-level, committable
  hooks location](https://code.claude.com/docs/en/hooks). Auto-firing events
  (`SessionStart`, `Setup`, `InstructionsLoaded`) tier at full strength;
  agent-triggered ones (`PreToolUse`, `PostToolUse`, …) are collected, tiered
  one level lower and labelled. The four non-command hook types (`http`,
  `mcp_tool`, `prompt`, `agent` — with `command`, the complete documented
  set) are reported, but never as command execution.

Both files permit comments and trailing commas, so the reader is a tolerant
JSONC parser in the same spirit as [the gyp lens](#the-gyp-lens-what-is-actually-inside-bindinggyp):
a file that will not parse is reported `partial` (with a raw-text hint when
`folderOpen` or an auto event name appears in the bytes), never passed
silently, never a crash. Every command string feeds the **same** shell-signal
extraction and `score()` that `audit` applies to a lifecycle script — the
risk ladder is not forked. Real output for a repo carrying both worm
artifacts:

```
.vscode/tasks.json:4  HIGH  folderOpen task "eslint-check" → node .vscode/setup.mjs (silent)
.claude/settings.json:3  HIGH  SessionStart hook → node .claude/setup.mjs
2 open-time execution entries found (2 HIGH).
```

`--deps` additionally downloads every locked dependency's tarball (cached,
like audit results) and scans it for shipped `.vscode`/`.claude` surfaces — a
folderOpen task inside a *package* is a payload, not a team convention, so it
is **HIGH regardless of command**.

The two surfaces gate very differently, and the tool prints each caveat next
to its own surface rather than one softened blend:

> **VS Code:** a `.vscode/tasks.json` finding means *"this runs once you
> trust this folder and allow automatic tasks"*, not *"this has run"* —
> [VS Code 1.117](https://code.visualstudio.com/docs/debugtest/tasks)
> defaults `task.allowAutomaticTasks` to `off` with a one-time Allow/Disallow
> prompt, workspace settings can no longer define that key, and automatic
> tasks never run in an untrusted workspace. The residual gap
> ([microsoft/vscode#309406](https://github.com/microsoft/vscode/issues/309406))
> is that the prompt does **not** display the command it is about to allow.
>
> **Claude Code:** a `SessionStart` finding means *"this runs on your next
> session in this trusted folder"* — there is **no hook review gate** before
> a project `.claude/settings.json` command hook fires (*"Claude Code doesn't
> use the same hook review gate as Codex"* — Datadog Security Labs, 2026-08).

Interpolations (`${workspaceFolder}`, `${CLAUDE_PROJECT_DIR}`) are kept
literal, never resolved. `.claude/settings.local.json` is out of scope — it
is machine-local and gitignored, so it neither ships in a tarball nor arrives
with a clone.

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

- **Optional dependency gap** ([npm/cli#9562](https://github.com/npm/cli/issues/9562)): `npm approve-scripts --allow-scripts-pending` never lists optional dependencies — but `npm ci --strict-allow-scripts` still rejects any optional dep with install scripts that is missing from `allowScripts`. The classic trap was `fsevents`: it only *installs* on macOS, so on a Linux CI runner nothing surfaced it, and strict mode failed the build anyway. **This one is fixed upstream** — [PR #9597](https://github.com/npm/cli/pull/9597) (merged 2026-06-23) makes the strict check skip **inert** nodes, since reify removes them before install scripts run; it shipped in **npm 11.18.0** and is in **npm 12.0.0**. So the detector is version-gated: on an npm carrying the fix it drops optional deps whose `os`/`cpu` exclude your platform (`!`-negated entries honored) and reports only the ones that really would install here; on an older npm nothing changes. The report tells you which npm it checked and the version the bug was fixed in.
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
      - uses: actions/checkout@v7
      - uses: Booyaka101/npm-script-lens@v1
        with:
          path: '.'               # dir or lockfile; npm/yarn/pnpm auto-detected
          fail-on-high: 'true'    # exit 1 when a HIGH-risk script appears
          comment-on-pr: 'true'   # post the report as a PR comment
```

The action writes the report to the job summary, comments on the PR (plain GitHub REST `issues/comments` call using `GITHUB_TOKEN` — same endpoint octokit uses), and fails the job when `fail-on-high` is true and a HIGH package exists.

Optional inputs: `diff-base` (audit only packages added/upgraded vs a base lockfile, e.g. one extracted from the PR base branch), `check-v12-gaps` (`auto`/`true`/`false` — the [npm v12 approve-scripts bug check](#npm-v12-approve-scripts-bug-check), auto-enabled when the runner's npm is v12+), `ci-check` (`'true'` to enable — the [allow --ci-check](#ci-guard) gate as a fail-fast Action step: fails the job when the runner's npm is v12+, a workflow runs `npm install`, and `package.json` has no `allowScripts` block, before the missing block silently breaks a downstream install), `sources-check` (`'true'` to enable — fails the job when the lockfile contains [git or remote-URL dependencies](#git-and-remote-dependencies-the-other-two-npm-v12-flips) the committed `.npmrc` `allow-git`/`allow-remote` doesn't correctly cover — insufficient, over-permissive, and invalid values all fail, with an `::error` annotation and a job-summary line), `publish-check` (`'true'` to enable — fails the job when a [CI publish path still authenticates with a long-lived npm token](#publish-will-your-release-workflow-survive-january-2027), which loses direct publish around January 2027, or is BROKEN by setup-node < v7 writing a dummy `_authToken` via `registry-url`; `::error` annotation, a job-summary line naming the verdict, and a `publish-token-cliff`/`publish-oidc-broken` result merged into the audit's SARIF file), `hooks-check` (`'true'` to enable — fails the job when the working tree carries a HIGH [open-time execution entry](#hooks-what-runs-when-the-folder-is-opened): a `.vscode/tasks.json` folderOpen task or an auto-firing `.claude/settings.json` command hook, with an `::error` annotation, a job-summary section, and a `hook-auto-run` result merged into the audit's SARIF file), `sync-check` (`'true'` — fails the job when the install-script allowlist has drifted from the lockfile; cross-ecosystem, auto-detects npm/pnpm/yarn/bun), and `sarif-file` for code scanning alerts:

```yaml
      - uses: Booyaka101/npm-script-lens@v1
        with:
          sarif-file: lens.sarif
      - uses: github/codeql-action/upload-sarif@v4
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
| `1` | an actionable failure: `audit --fail-on-high` found HIGH/malicious · `sync --check`/`manifest --check` drift · `allow --ci-check` would break on npm v12 · `sources --check` found insufficient/over-permissive/invalid allow-git/allow-remote config · [`publish --check`](#publish-will-your-release-workflow-survive-january-2027) found a TOKEN or BROKEN publish path (UNKNOWN never fails) · [`hooks --check`](#hooks-what-runs-when-the-folder-is-opened) found an open-time execution entry at or above the `--fail-on` floor · `doctor` detected npm drift · `diff` found an added/modified install script |
| `2` | a usage/runtime error (bad ref, missing lockfile, unreadable input) |

## Commands at a glance

| command | does |
|---|---|
| `audit` | scan a lockfile, report install-script risk (Markdown/JSON/SARIF); `--fail-on-high`, `--diff`/`--since`, `--check-v12-gaps` |
| `allow` | split scripted packages into an auto-approved allowlist + `_review`, in your manager's native format; `--write`, `--ci-check`, `--manager`, `--policy` |
| `review` | show pending approvals **with the actual script content** + verdict; `--output-allowscripts` writes decisions |
| `diff` | compare a package's install scripts (+ implicit node-gyp) across two versions; exit 1 on any add/modify; `--json` |
| `sources` | git + remote-URL deps vs npm v12's `allow-git`/`allow-remote`: ROOT/TRANSITIVE per dep, minimal correct `.npmrc`; `--check`, `--write`, `--json` |
| [`publish`](#publish-will-your-release-workflow-survive-january-2027) | classify every CI publish path (TRUSTED/STAGED/TOKEN/BROKEN/UNKNOWN) vs npm's January-2027 token cliff and the setup-node < v7 OIDC breakage, with the migration patch + npmjs.com checklist; `--check`, `--json`, `--sarif` |
| [`hooks`](#hooks-what-runs-when-the-folder-is-opened) | the open-time surface: `.vscode/tasks.json` folderOpen tasks + `.claude/settings.json` hooks, same risk ladder as `audit`; `--check`, `--fail-on`, `--deps` (dependency tarballs — shipped entries are HIGH regardless), `--json`, `--sarif` |
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

## Related

[**pnpm11-ci-guard**](https://github.com/Booyaka101/pnpm11-ci-guard) — the other half of
the build-script story on pnpm v11.

Once this tool writes an `allowBuilds` allowlist into `pnpm-workspace.yaml`, a
`pnpm install` inside Docker will **prompt for approval and hang the build** unless the
image sets `ENV CI=true`. pnpm11-ci-guard catches that, plus the rest of the v10 → v11
migration that lands in Dockerfiles and CI workflows — `npm_config_*` env vars that v11
silently stopped reading, and images that never `COPY pnpm-workspace.yaml`. pnpm's own
codemod covers neither.

Use npm-script-lens to decide *what may build*; use pnpm11-ci-guard to make sure your
image and CI still work once you have decided.
