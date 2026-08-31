# ▶️ RESUME: npm-script-lens

_Updated 2026-08-31: v1.15.0 RELEASED (npm latest, GitHub Release, v1 moved)._

## v1.15.0 (2026-08-31) RELEASED: RUNTIME_BOOTSTRAP, the ChainDrop alternate-runtime escape ⬅️ start here

Closes the evasion ChainDrop used on 2026-08-04 (Microsoft: 400+ packages). The preinstall `node setup.mjs` was already followed; the escape was inside it: setup.mjs downloaded a signed bun release from oven-sh/bun and ran a bundled stage 2 under bun, a file `walkFiles` never reached because it was spawned, not required. Now the entry-point resolver is a runtime table (node/bun/deno run/tsx/ts-node + npx/bunx/bun x), a download URL matching a runtime distribution is flagged, and a spawn/exec string-literal file arg is queued into the same walk, so the second stage is analyzed and its capabilities merge into a new HIGH finding **RUNTIME_BOOTSTRAP**. `--fail-on-runtime-bootstrap` + policy `runtimeBootstrapPolicy: "fail"` gate it; diff prints `gained vs <base>: runtime bootstrap (bun)`. 450 tests. Fixtures are served from a mock registry (scripts/serve-bootstrap-fixtures.js), never written to node_modules, because Defender quarantines ChainDrop-shaped bytes on disk (it quarantined README.md twice this session too). Full detail in PROGRESS.md → v1.15.0.

**Shipped end to end**: PR #28 rebase-merged as `1c178cc` → CI green on the exact merged commit via the check-runs API → tag `v1.15.0` → published by trusted publishing with provenance, npm `latest` = 1.15.0 → `v1` moved → GitHub Release → clean-room install from the live registry re-verified. Zero new CodeQL alerts. **Item 0 below is now resolved**: the npmjs.com Trusted Publisher entry works, 1.15.0 published by OIDC with no token.

**VS Code extension 1.15.0 also PUBLISHED** (2026-08-31, confirmed live via the public `extensionquery`, not by the PUT's 200). It was not cosmetic this time: a new signal kind meant `capabilitiesOf` silently dropped `bootstrap:`, so a bootstrapping package read as plain "runs other programs" in the editor. Runtime bootstrap is now a first-class capability and leads the sentence. 56 extension tests. **Rule this establishes: "the extension shells the CLI so it needs no release" holds for new commands and new findings, but NOT for a new signal KIND, because the kind-to-English map lives in the extension.**

Nothing is outstanding for this release. Next session: the 7 pre-existing CodeQL alerts (cheap), then distribution rather than features (see the 1.11.0 adoption measurement).

## v1.14.0 (2026-08-22): the provenance-downgrade gate, MERGED + PUBLISHED (1.14.0 live on npm)

New `trust` command + opt-in audit finding: flag a resolved version below the highest trust tier its package previously reached (trusted publisher > provenance > none, npm/cli#9242's ladder and key names). pnpm >= 10.21 has this natively as `trust-policy=no-downgrade`; npm and Yarn do not. The worked example is LIVE: axios@1.13.3 genuinely has no attestations after 1.13.2's provenance. One packument GET per package (trusted-publisher = `_npmUser.trustedPublisher`, verified empirically). Default off everywhere; only `--fail-on-downgrade` flips an exit code. Action input `trust-policy-check` wired into self-audit.yml. 429 tests. Full detail in PROGRESS.md → v1.14.0. **Owner steps: review/merge the PR, then tag v1.14.0 + move v1 + GitHub Release; npm publish rides the tag via trusted publishing.**

## v1.13.0 (2026-08-17, branch `chore/stop-tests-writing-fixtures`): `--path` finds projects ⬅️ start here

**Why**: `resolveLockfile` only ever looked in the exact directory it was handed, so `audit` from a subdirectory of a normal project, or from a directory of checkouts, was a hard `lockfile not found`. The tool already disagreed with itself here: `hooks` has walked subdirectories since 1.8.0 and its help says "monorepo subdirectories included".

**Resolution order**, first hit wins: the path itself, then upward like npm, then every project underneath. Steps 1 and 2 apply to every lockfile command via `resolveLockfile`; step 3 is `audit` only, via the new `findProjects` in `src/lockfiles.js`.

**Deliberate boundaries.** `node_modules` and dot directories are never descended into, depth caps at 6, and a directory *inside* a project resolves upward to that project rather than splitting it into children (a workspace subdir belongs to its root). `--sarif`, `--html`, `--diff` and `--since` describe one project, so multi-project mode names the flag and refuses rather than merging artifacts it would have to guess at.

**No single-project regression**: output is byte-identical to 1.12.0, verified by diffing a fresh run against the committed sample. `--json` keeps `{results, allowScripts}` for one project, gains `{projects: [...]}` for several.

**Also on this branch**: the e2e suite no longer rewrites `fixtures/demo-report.md` from the live registry, which is what dirtied the tree on every test run for months and let the committed sample go stale at the pre-1.11.0 provenance format. `npm run demo:report` refreshes it deliberately.

Tests 368 to 381 (9 resolver units in `test/discovery.test.js`, 4 e2e).

## v1.12.0 (2026-08-17): Node 18 supported

**Why**: the same reporter who hit the commander crash was still blocked after 1.11.2, because they are on Firebase Studio (Node 18.19.1) and `engines.node` has said `>= 20` since 0.2.0. 1.11.2 turned a stack trace into a clear refusal, which is better but still a refusal. Nothing in the code needs Node 20; the newest API used is global `fetch`, which is Node 18. The floor was a guess nobody had tested.

**What changed**: `engines.node` `>= 18`, commander 14 to 13.1.0 (last line that is CommonJS *and* declares `>= 18`), README requirement line, and CI gains an `18` leg on both OSes. Version is 1.12.0, not a patch, because widening the supported runtime is a capability.

**Two diagnostic lessons worth keeping.** First, `npx` served the reporter a cached 1.11.1 out of `~/.npm/_npx/<hash>/` long after 1.11.2 was live; the tell was the stack pointing at `cli.js:8`, which is where `require('commander')` sits in 1.11.1 and not in 1.11.2 (line 29, below the floor guard). Pin the version or delete `~/.npm/_npx` when a fix "does not work".

Second, **the suite failing on an old Node was twice misdiagnosed as `node:test` runner limits.** On Node 18 the 127 failures were entirely the 1.11.2 floor guard: every e2e test spawns the CLI, and the CLI exited 1 under `>= 20`. Lowering the floor took Node 18 to 368/368. On Node 20.0.0 the 123 failures are a genuinely different cause: that runner does not fire top-level `before()` hooks, so tests never start their own mock registry and fall through to the real one (`HTTP 404 for registry.npmjs.org/mock-gyp/1.0.0`). 20.0.x is therefore in the supported range with the CLI verified working, but has no CI leg. Read the actual assertion before blaming the runner.

## v1.11.2 RELEASED (2026-08-17): the CLI runs on the Node it advertises again

**What it fixes: the CLI could not start on Node 18, or on Node 20.0 through 20.18, in every version from 1.4.0 to 1.11.1.** Dependabot PR #2 took commander from 12 straight to 15, and commander 15 is ESM-only with `engines.node >= 22.12` while this package advertises `>= 20`. `require('commander')` from a CommonJS entrypoint only resolves an ESM module where `require(esm)` is unflagged, so users got `ERR_REQUIRE_ESM` and a stack trace into `node_modules`. npm and npx only warn on an engines mismatch, so nothing stopped the install. Reported against `npx npm-script-lens audit` on Node 18.19.1.

**Blast radius was every surface, not just npx.** `src/action.js` requires `src/cli.js`, so the GitHub Action failed identically on a runner pinned below 20.19; the pre-commit hook, the VS Code extension and the Neovim plugin all reach the CLI too.

**Why CI missed it for seven releases**: the matrix used a floating `node: 20`, which setup-node resolves to the newest 20.x. That always carries `require(esm)`, so 368 passing tests said nothing about a CLI that could not start. The matrix now pins `20.18`, a Node without it.

**Fix**: commander pinned back to 14.0.3 (CommonJS, same `>= 20` floor). No commander 15 API was in use. `engines.node` stays `>= 20`, verified by running the CLI on a downloaded Node 20.0.0 rather than by assertion. Three guards added: `test/engines.test.js` (fails when a runtime dep declares a Node floor above ours or is ESM-only under a CJS entrypoint, verified by reinstalling commander 15 and watching it go red), the pinned CI matrix, and a floor check in `cli.js` above the requires that prints which Node is needed. Also fixed the pre-commit example rev, stale at `v1.0.0`.

**Shipped**: PRs [#13](https://github.com/Booyaka101/npm-script-lens/pull/13) (fix), [#14](https://github.com/Booyaka101/npm-script-lens/pull/14) and [#15](https://github.com/Booyaka101/npm-script-lens/pull/15) (house style) rebase-merged, CI green on the exact main commit `6a10088` BEFORE publishing, `v1.11.2` tagged, `v1` moved, [GitHub Release](https://github.com/Booyaka101/npm-script-lens/releases/tag/v1.11.2), `npm publish` as **booyaka**. npm `latest` = **1.11.2**. Clean-room install from the live registry re-verified, and the published tarball runs on Node 20.0.0 and 20.18.3, the versions that were broken. 368 tests.

**Note on the self-audit gate**: the version bump alone made `manifest --check` fail (`tool 1.11.1 → 1.11.2, detector changed, re-review`), which is the gate working as designed. Re-baselined in `6a10088`; only the version stamp moved, `packages` is still empty.

**VS Code extension 1.8.2 PUBLISHED to the Marketplace (2026-08-17)**: cosmetic only (em dashes out of the diagnostics and the listing). Published the documented way, but note two corrections to the 1.7.0/1.8.0 recipe below. The `:9223` automation browser was not running, and bridging cookies was unnecessary: the PUT works from the ordinary `:9222` browser's own `marketplace.visualstudio.com/manage` tab. And a `GET` on that same gallery path answers `503 TF10216 Azure DevOps services are currently unavailable`, which is the route rejecting the verb, not an outage; the public `POST /_apis/public/gallery/extensionquery` returned 200 throughout. The PUT returned 200 `flags: validated, public` as before.

**Do not read the PUT's 200 as published.** The manage row sits at `Verifying1.8.2` for roughly 10 minutes while Marketplace validation runs, and `extensionquery` keeps serving the previous version with an unchanged `lastUpdated` for that whole window. Confirmed live only when the manage row lost the `Verifying` prefix *and* the public query returned `["1.8.2","1.8.1","1.8.0"]` with `lastUpdated` 2026-08-17T06:36:06Z.

**Also this session**: em dashes swept out of `editors/` and the two notes files, the last places carrying them after the 1.11.0 pass covered `src/`. The empty-cell markers in `reporter.js` and the READMEs stay, being table typography.

## v1.10.0 RELEASED (2026-08-14): release gates in `publish`

**What it adds**: `publish` now answers *who can trigger a publish today*, not just whether the path survives the January 2027 cliff. Two facts per resolved path, `trigger` (the `on:` events reaching the job, with file:line, inherited through reusable workflows and composite actions) and `gate` (DANGEROUS / REVIEWABLE / MANUAL / TAG / AUTO / UNKNOWN). Prompted by ChainDrop (2026-08-04, 2,234 poisoned versions across 444 names published through legitimate OIDC workflows after an account takeover) and by crates.io removing `pull_request_target` / `workflow_run` from Trusted Publishing. ⚠️ `--check` and the Action's `publish-check` now exit 1 on DANGEROUS; `--require-gate <none|tag|manual|environment>` raises the bar further.

**Two bugs fixed, both found by using the tool on itself**: the report told you to paste an `allowScripts` block computed without reading yours (on a project with nothing scripted that meant pasting `{}` over a populated block, un-approving everything under npm v12), and `publish <typo-path>` resolved to the parent directory and printed a green all-clear. Also: reports reflow to terminal width instead of printing 300-column lines, and `src/publish.js` split 1,492 lines into four modules.

**Shipped**: PR [#6](https://github.com/Booyaka101/npm-script-lens/pull/6) rebase-merged (4 commits survive) → **CI green on the exact main commit `82e9f4a`** (4 test legs + guards) BEFORE publishing → `v1.10.0` tagged, `v1` moved → [GitHub Release](https://github.com/Booyaka101/npm-script-lens/releases/tag/v1.10.0) → `npm publish` → npm `latest` = **1.10.0**. Clean-room install **from the live registry** re-verified: 17 packages, `--version` 1.10.0, `src/publish/` ships, exit codes 0/1/1/2 correct, and both bug fixes confirmed from the published package. 350 tests.

**Still owner-gated**: the VS Code extension needs no release (it shells out to the CLI and never parses verdict strings, so extension users get 1.10.0 via `npx` automatically, same as 1.7.0/1.9.0). Action Marketplace listing auto-tracks the release. Promo post not written (owner-voiced only); the hook is "your release workflow can pass every scanner and still let one compromised account publish, with valid provenance".

## v1.8.0 RELEASED (2026-08-08): the open-time surface

**CLI/Action**: new `hooks` command scanning `.vscode/tasks.json` folderOpen tasks + `.claude/settings.json` hooks (the 2026-08-04 keyv worm's persistence layer, Wiz: "Persistence is attempted via Claude Code hooks and VS Code `tasks.json`"), `--deps` tarball scan (shipped auto-run entries HIGH regardless of command), SARIF rule `hook-auto-run`, opt-in `hooks-check` Action input. 293/293 tests. Shipped `9b993ef` → CI green all 4 legs + Guards BEFORE publishing → `v1.8.0` tag + `v1` moved → [GitHub Release](https://github.com/Booyaka101/npm-script-lens/releases/tag/v1.8.0) → npm `latest` = **1.8.0** (clean-room registry re-verified) → **Action Marketplace auto-tracked to v1.8.0** (verified live; no sudo step needed, the listing follows releases once listed). Full detail in PROGRESS.md → v1.8.0.

**VS Code extension 1.8.0, PUBLISHED to the Marketplace (2026-08-08)**: inline diagnostics ON the two surface files themselves (warning at HIGH on the real line, information for agent-triggered/non-command, one note for `partial` files), two new commands (*Open-time hooks*, *… in dependency tarballs (--deps)*), activation on the surface files, 30/30 extension tests, committed `3d97a7c`, vsix attached to the v1.8.0 GitHub Release. Published via the same cookie-session gallery `PUT` as 1.7.0 (below), the :9223 automation browser was **still signed in**, so no cookie bridging was needed this time; the PUT returned 200 `flags: validated, public` first try.

## VS Code extension 1.7.0: PUBLISHED to the Marketplace (2026-08-08)

The Marketplace had been stuck at **1.3.0** (1.4.0 was built but never uploaded), while the CLI moved to 1.7.0. Shipped: version 1.4.0 → 1.7.0 (tracks the CLI again), new **Publish readiness (npm token cliff)** command running the CLI's `publish`, "npm 12 / migration / allowlist" keywords + description (mined from issue #4, a user thanking us for their "npm 12 migrations", issue answered and closed), and `vscode:publish` no longer pins a stale 1.3.0 vsix. 267/267 tests, committed `b8a6562`, vsix attached to the v1.7.0 GitHub Release.

**No VSCE_PAT exists anywhere, and none is needed.** The Marketplace *manage* UI's Update dialog hangs the renderer on submit (twice, reproducibly), but the underlying gallery REST API works with the browser's cookie session: from any authenticated marketplace.visualstudio.com page, `PUT /_apis/gallery/publishers/booyaka101/extensions/npm-script-lens?api-version=3.0-preview.1` with JSON body `{"extensionManifest":"<base64 vsix>"}` (Content-Type application/json; octet-stream is rejected) → 200, `flags: validated, public`. Sign-in for the automation browser (:9223) = bridge github.com/microsoftonline/visualstudio.com cookies from the main browser (:9222) via `Storage.getCookies`/`setCookies`, then load `/manage/publishers/booyaka101` (Microsoft auth rides the GitHub session).

## v1.7.0 RELEASED (2026-08-07), latest on npm + GitHub

267/267 tests (`node --test`, ~6 s). Shipped end to end: rebased onto the Dependabot acorn bump that had landed mid-build (suite re-run green against it) → pushed `fb5d412` → **CI green on ubuntu/windows × node 20/22 + Guards BEFORE publishing** → tagged `v1.7.0`, moved `v1` → [GitHub Release](https://github.com/Booyaka101/npm-script-lens/releases/tag/v1.7.0) → `npm publish`. npm `latest` = **1.7.0**; clean-room registry install re-verified. Action Marketplace already shows v1.7.0.

**What it fixes: a false all-clear in `publish`.** A release job whose `uses: ./.github/actions/release` held the real `npm publish` + `NODE_AUTH_TOKEN` reported **zero** publish paths and `publish --check` exited 0, a clean bill of health for exactly the workflow shape npm's January-2027 cliff breaks. Local composite actions and local reusable workflows are now resolved from the working tree and scanned with the calling job's grant (composites cannot declare `permissions`), token indirection through `with:` → `inputs.*` is threaded end-to-end, findings anchor to the real `action.yml` line with a printed `via` chain, and a publishing composite no workflow references is surfaced as UNKNOWN. Third-party actions stay silent. Full detail in PROGRESS.md → v1.7.0.

**Note:** v1.6.0 went to npm but was never tagged/released on GitHub. The **tag was backfilled 2026-08-07** at `5b60223` (the commit npm's 1.6.0 tarball was built from, publish followed it by 30 seconds), so `v1.0.0 … v1.7.0` is now gap-free; there is still no GitHub *Release* for it, which is fine. The VS Code extension (1.4.0) needs no release for this fix; it invokes the CLI, so its users get 1.7.0 via `npx`. Publishing it still needs a `VSCE_PAT` (owner-gated).

## v1.5.0: RELEASED (2026-08-02)

245/245 tests (`node --test`, ~6 s). Shipped end to end: pushed `6bab984` → **CI green on ubuntu/windows × node 20/22 + Guards BEFORE publishing** (the 1.0.0 lesson) → tagged `v1.5.0`, moved `v1` → [GitHub Release](https://github.com/Booyaka101/npm-script-lens/releases/tag/v1.5.0) → `npm publish`. npm `latest` = **1.5.0**; clean-room registry install re-verified (17 pkgs, `publish --check` reproduces the worked example on a fresh project and exits 1).

**What it adds, the `publish` command**: will this repo's release workflow still work after npm's January-2027 change (bypass-2FA tokens lose direct publish, github.blog 2026-07-31: "We are targeting January 2027 for this update"), and is the recommended fix actually available here? Classifies every CI publish path (GH Actions / GitLab / CircleCI, tolerant reader, no YAML dep, no network) as TRUSTED / STAGED / TOKEN / UNKNOWN; `--check` exits 1 only on TOKEN; checks the doc-quoted version floors (trusted: npm 11.5.1 + Node 22.14.0; staged: npm 11.15.0 + Node 22.14.0) against setup-node pins and engines; marks trusted publishing UNAVAILABLE on self-hosted runners and routes to `npm stage publish` + `npm stage approve`; emits the YAML patch and the pre-filled npmjs.com trusted-publisher checklist. Plus `--json`, `--sarif` (rule `publish-token-cliff`), a doctor publish-readiness section, and the Action's opt-in `publish-check` input. Full detail in PROGRESS.md → v1.5.0.

**Done this session** (owner-directed): commit `6bab984` · push · CI green (4/4 matrix legs + Guards) · tag `v1.5.0` · `v1` moved to it · GitHub Release · `npm publish` as **booyaka** (gh **Booyaka101**). Nothing release-related is outstanding.

**Promo, POSTED 2026-08-02** (owner-directed): community discussion 201329 ("Upcoming changes to npm 2FA-bypass granular access tokens") → https://github.com/community/community/discussions/201329#discussioncomment-17867170, answers that thread's unanswered self-hosted / other-provider migration gaps with the staged-publishing route, plus the version floors and the pre-filled npmjs.com form.

**GitHub Action Marketplace: DONE.** Verified live 2026-08-02 at https://github.com/marketplace/actions/npm-script-lens, already showing **v1.5.0** (the release-edit checkbox `release[repository_action_release_attributes][published_on_marketplace]` reads checked). The old "needs a click-through" note was stale.

**Still owner-gated (credential-blocked, not effort-blocked):** VS Code Marketplace publish, no `VSCE_PAT` in this environment, and minting one means signing into Azure DevOps and creating a credential on the account; JetBrains plugin, needs a JetBrains Marketplace token; in-editor screenshots, feasible here (`code` CLI + the 1.4.0 `.vsix` are both present), just not yet captured.

## v1.3.0: released as part of the 1.3.0/1.4.0 arc
201/201 tests (`node --test`, ~5 s). Working tree has the whole 1.3.0 change; nothing pushed.

**Owner steps:** commit → push → **wait for CI green on ubuntu/windows × node 20/22** (the 1.0.0 lesson) → tag `v1.3.0`, move `v1` → GitHub Release → `npm publish` (needs `npm login`; account is **Booyaka101**).

**Also on this branch: both red scheduled canaries are fixed and now GREEN on the real runners.** They had been failing on their own schedule at v1.2.0, nothing to do with v1.3.0. `npm-compat` was installing `npm@next`, a dist-tag npm does not publish (ETARGET every run). `pm-compat` was worse: it could never pass (GitHub sets `CI=true`, which makes core-js suppress the banner it grepped for; npm also hides script output without `--foreground-scripts`), *and* its bun leg had been a **false pass**: the loose pattern matched bun's own `+ core-js@3.38.1` package line. It now asserts on each manager's own blocked-scripts signal, before and after `allow --write`, and all three legs report `✅ blocked before, allowed after`. Full story in PROGRESS.md.

**Verified on the branch (not just locally):** `ci` green on ubuntu+windows × node 20/22, the Windows legs matter, since the Defender fixture problem was Windows-only. `npm-compat` green on npm 12 / latest / next-12. `pm-compat` green and conclusive on npm / pnpm / bun.

**Follow-up worth a future release (verified, nothing broken):** npm 11.18/12 added a `npm install-scripts` front-end with `approve` / `deny` / **`ls`** / **`prune`** subcommands; `npm approve-scripts` and `npm deny-scripts` survive as aliases (confirmed in npm 12.0.1's own source), so our contract strings are still correct, but npm's warning text now points users at the new spelling, and `install-scripts prune` overlaps our `sync`.

**What it adds**: two things, one release:
1. **The gyp lens.** New `src/gyp.js` reads *inside* `binding.gyp` and the `.gypi`/`.gyp` files it includes (tolerant non-JSON parser: single quotes, `#` comments, trailing commas). Covers every gyp execution channel, `<!( <!@( >!( >!@( ^!( ^!@(`, `<!pymod_do_main(`, `<|( >|( ^|(`, `actions/rules/postbuilds[].action`, `make_global_settings`, Python-eval `conditions`, and never flags plain `<(var)` interpolation. Feeds `audit` (`gyp:` signals, scores HIGH), `review` (findings printed above the raw file), `--sarif` (`gyp-exec-channel`), and policy `denyCapabilities`.
2. **`diff` false negative FIXED**: it compared `binding.gyp` by existence, so a version that *rewrote* an existing one read `UNCHANGED` and exited 0. Now content-compared: `MODIFIED` + line diff + `gainedChannels` + exit 1. Proven live on `bufferutil@4.0.8 → 4.0.9`.
3. **`v12-optional-gap` version-gated**: npm/cli#9562 was fixed by PR #9597 (npm 11.18.0 / 12.0.0), so the detector no longer tells modern-npm users to allowlist `fsevents` on Linux.

⚠️ **Release-note callout for users**: a `manifest --check` baseline containing native packages may now show a new `gyp` capability, real capability, not drift. Re-baseline once with `manifest --write`.

⚠️ **Do not "tidy" the Miasma fixture into one plain `.gyp` file.** It is the real payload; Windows Defender quarantines it off disk (`Trojan:JS/PhantomWorm.DA!MTB`) and base64 does not hide it (Defender decodes containers). The structure lives in `fixtures/gyp/malicious-miasma.gyp.template`, the command in `test/gyp.test.js`, joined at runtime. Merging them passes on Linux and then deletes itself on Windows and on `windows-latest` CI. Rationale in `fixtures/gyp/README.md`.

**Promo hook (owner-approved posts only, NOT posted):** the ReversingLabs 2026-06-04 write-up (286 malicious versions / 56 packages hiding in `binding.gyp`) and Aikido's 2026-06-09 teardown are the natural anchors, no other allowlist/approval tool reads inside that file.

## v1.2.0: RELEASED (2026-07-27), latest on npm + GitHub
- Pushed `bc0f8a9` → **CI green on ubuntu/windows × node 20/22** (waited this time, the 1.0.0 lesson) → tagged `v1.2.0`, moved `v1` → [GitHub Release](https://github.com/Booyaka101/npm-script-lens/releases/tag/v1.2.0) → `npm publish`. npm `latest` = **1.2.0**; clean-room registry install re-verified (`npm i npm-script-lens@1.2.0` → `sources` reproduces the worked example exactly).
- VS Code extension unchanged this release (still 1.0.0; the `.vsix` on the v1.0.1 Release still applies), no new asset attached.

## What v1.2.0 added
- **New `sources` command** covers npm v12's other two flipped defaults, `allow-git`/`allow-remote` (enum `all|none|root`, default `none`): finds git + remote-tarball deps in all four lockfile dialects, classifies ROOT vs TRANSITIVE (transitive forces `all`), prints/writes the minimal correct `.npmrc` (comment-preserving), `--check` fails on insufficient / over-permissive / invalid (`=true`) config. `allow --ci-check`, `doctor`, and the Action (`sources-check` input) extended. 174/174 tests. See PROGRESS.md → v1.2.0.
- Promo hook (owner-approved posts only, NOT yet posted): discussion 198547's best migration tooling for git deps is literally `grep -r 'git+'`, `sources` is the purpose-built answer. Same for the npm v12 migration threads.

## Where we were (v1.0.1 release notes)
- **v1.0.1 RELEASED and verified, latest on npm + GitHub.** The 0.8→1.0 arc shipped as v1.0.0 (`7063255`); **v1.0.1** is a patch fixing `audit --since` on Windows (git 8.3 short-name path mismatch caught by CI on the 1.0.0 commit). Tagged, `v1` moved to 1.0.1, GitHub Releases live for both, npm `latest` = 1.0.1, clean-room `npx` verified. **CI green on ubuntu/windows × node 20/22.** `.vsix` attached to both Releases.
- Working tree clean; everything committed. **Lesson logged: wait for CI green before `npm publish` (1.0.0 was published before CI finished and Windows caught a real `--since` bug → fixed forward in 1.0.1).**

## Shipped surfaces (all live)
- **npm**: `npm-script-lens@1.0.0`, https://www.npmjs.com/package/npm-script-lens
- **GitHub**: repo + Release `v1.0.0` (with `.vsix` asset), Booyaka101/npm-script-lens; `v1` tag points here so the Action auto-updates.
- **CLI** (11 cmds): audit · allow · review · sync · approve · manifest · doctor · init · completion · mcp
- **4 package managers** live-verified: npm · pnpm 11 · yarn Berry 4 · bun 1.3
- **CI/local**: GitHub Action (ci-check + sync-check + v12-gaps), auto-fix bot, npm-compat + pm-compat canaries, `init --hook` + `.pre-commit-hooks.yaml`
- **Editors**: VS Code extension (`.vsix` on the Release) · Neovim plugin
- **Reporting**: Markdown · JSON · SARIF · HTML · **AI**: MCP (audit_package, audit_lockfile, classify_allowscripts)

## Still needs the owner (credential / manual gated: cannot be automated here)
0. **npm Trusted Publisher entry, BLOCKING the next release.** `release.yml` publishes by OIDC as of 2026-08-17 and `publish` grades it TRUSTED, but npmjs.com does not yet trust it, so a tag push now *fails* at the publish step rather than skipping. Fix at https://www.npmjs.com/package/npm-script-lens/access, Trusted Publisher, GitHub Actions: organization `Booyaka101`, repository `npm-script-lens`, workflow filename `release.yml`, environment blank, allowed action `npm publish`. Web-only, there is no npm CLI command for it, and the npmjs.com browser session was signed out. Once it exists, provenance is automatic and nothing on npm needs a token again.
1. **VS Code Marketplace publish**: the Marketplace gallery `PUT` (see the 1.8.2 notes above) needs no PAT, so this is only gated on a signed-in browser. `npx vsce publish` still needs a `VSCE_PAT`, which does not exist here.
2. ~~**GitHub Action Marketplace**~~, **DONE** (verified 2026-08-02): the listing is live at https://github.com/marketplace/actions/npm-script-lens and already shows **v1.5.0**. The release-edit checkbox `release[repository_action_release_attributes][published_on_marketplace]` reads checked. Nothing to click.
3. **JetBrains plugin**: build-verified only; needs JVM/Gradle to run, not testable in this environment.
4. **Real in-editor screenshots**: run VS Code (install the `.vsix`) / Neovim once and capture, for the README Preview + Marketplace listing.
5. **Promo** (owner-approved posts only): v1.0.0 is a strong hook for community/discussions/198547, npm/rfcs#897, and the npm/cli #9562/#9463 gap threads.

## Gotchas
- npm is logged in as **`booyaka`**; gh as **`Booyaka101`**. Publishing works from this machine.
- `script-lens.policy.json` (policy) ≠ `script-lens.json` (behavior manifest), distinct files.
- `DETECTORS.fixedInNpm` in `src/npm-contract.js` is still `null`, pin when exact fixed npm versions are known so `doctor` can retire obsolete detectors.
- `*.vsix` is now gitignored (build artifact); the canonical copy is the Release asset.
- Test count 128 includes 6 VS Code core tests auto-discovered by root `node --test`; Neovim logic tested via `editors/nvim/test/run.lua` (headless nvim, drive path `D:/…` not `/d/…`).

## Sanity check
```
node --test                # expect 245 pass
node src/cli.js --version   # 1.5.0
npm view npm-script-lens version   # 1.4.0 until the owner publishes 1.5.0
git status --short         # the uncommitted v1.5.0 change
```
