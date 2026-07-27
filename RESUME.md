# ▶️ RESUME — npm-script-lens

_Updated 2026-07-27 after building v1.3.0._

## v1.3.0 — BUILT, GREEN, NOT YET RELEASED ⬅️ start here
201/201 tests (`node --test`, ~5 s). Working tree has the whole 1.3.0 change; nothing pushed.

**Owner steps:** commit → push → **wait for CI green on ubuntu/windows × node 20/22** (the 1.0.0 lesson) → tag `v1.3.0`, move `v1` → GitHub Release → `npm publish` (needs `npm login`; account is **Booyaka101**).

**Also on this branch: both red scheduled canaries are fixed and now GREEN on the real runners.** They had been failing on their own schedule at v1.2.0 — nothing to do with v1.3.0. `npm-compat` was installing `npm@next`, a dist-tag npm does not publish (ETARGET every run). `pm-compat` was worse: it could never pass (GitHub sets `CI=true`, which makes core-js suppress the banner it grepped for; npm also hides script output without `--foreground-scripts`), *and* its bun leg had been a **false pass** — the loose pattern matched bun's own `+ core-js@3.38.1` package line. It now asserts on each manager's own blocked-scripts signal, before and after `allow --write`, and all three legs report `✅ blocked before, allowed after`. Full story in PROGRESS.md.

**Verified on the branch (not just locally):** `ci` green on ubuntu+windows × node 20/22 — the Windows legs matter, since the Defender fixture problem was Windows-only. `npm-compat` green on npm 12 / latest / next-12. `pm-compat` green and conclusive on npm / pnpm / bun.

**Follow-up worth a future release (verified, nothing broken):** npm 11.18/12 added a `npm install-scripts` front-end with `approve` / `deny` / **`ls`** / **`prune`** subcommands; `npm approve-scripts` and `npm deny-scripts` survive as aliases (confirmed in npm 12.0.1's own source), so our contract strings are still correct — but npm's warning text now points users at the new spelling, and `install-scripts prune` overlaps our `sync`.

**What it adds** — two things, one release:
1. **The gyp lens.** New `src/gyp.js` reads *inside* `binding.gyp` and the `.gypi`/`.gyp` files it includes (tolerant non-JSON parser: single quotes, `#` comments, trailing commas). Covers every gyp execution channel — `<!( <!@( >!( >!@( ^!( ^!@(`, `<!pymod_do_main(`, `<|( >|( ^|(`, `actions/rules/postbuilds[].action`, `make_global_settings`, Python-eval `conditions` — and never flags plain `<(var)` interpolation. Feeds `audit` (`gyp:` signals, scores HIGH), `review` (findings printed above the raw file), `--sarif` (`gyp-exec-channel`), and policy `denyCapabilities`.
2. **`diff` false negative FIXED** — it compared `binding.gyp` by existence, so a version that *rewrote* an existing one read `UNCHANGED` and exited 0. Now content-compared: `MODIFIED` + line diff + `gainedChannels` + exit 1. Proven live on `bufferutil@4.0.8 → 4.0.9`.
3. **`v12-optional-gap` version-gated** — npm/cli#9562 was fixed by PR #9597 (npm 11.18.0 / 12.0.0), so the detector no longer tells modern-npm users to allowlist `fsevents` on Linux.

⚠️ **Release-note callout for users**: a `manifest --check` baseline containing native packages may now show a new `gyp` capability — real capability, not drift. Re-baseline once with `manifest --write`.

⚠️ **Do not "tidy" the Miasma fixture into one plain `.gyp` file.** It is the real payload; Windows Defender quarantines it off disk (`Trojan:JS/PhantomWorm.DA!MTB`) and base64 does not hide it (Defender decodes containers). The structure lives in `fixtures/gyp/malicious-miasma.gyp.template`, the command in `test/gyp.test.js`, joined at runtime. Merging them passes on Linux and then deletes itself on Windows and on `windows-latest` CI. Rationale in `fixtures/gyp/README.md`.

**Promo hook (owner-approved posts only, NOT posted):** the ReversingLabs 2026-06-04 write-up (286 malicious versions / 56 packages hiding in `binding.gyp`) and Aikido's 2026-06-09 teardown are the natural anchors — no other allowlist/approval tool reads inside that file.

## v1.2.0 — RELEASED (2026-07-27), latest on npm + GitHub
- Pushed `bc0f8a9` → **CI green on ubuntu/windows × node 20/22** (waited this time — the 1.0.0 lesson) → tagged `v1.2.0`, moved `v1` → [GitHub Release](https://github.com/Booyaka101/npm-script-lens/releases/tag/v1.2.0) → `npm publish`. npm `latest` = **1.2.0**; clean-room registry install re-verified (`npm i npm-script-lens@1.2.0` → `sources` reproduces the worked example exactly).
- VS Code extension unchanged this release (still 1.0.0; the `.vsix` on the v1.0.1 Release still applies) — no new asset attached.

## What v1.2.0 added
- **New `sources` command** covers npm v12's other two flipped defaults, `allow-git`/`allow-remote` (enum `all|none|root`, default `none`): finds git + remote-tarball deps in all four lockfile dialects, classifies ROOT vs TRANSITIVE (transitive forces `all`), prints/writes the minimal correct `.npmrc` (comment-preserving), `--check` fails on insufficient / over-permissive / invalid (`=true`) config. `allow --ci-check`, `doctor`, and the Action (`sources-check` input) extended. 174/174 tests. See PROGRESS.md → v1.2.0.
- Promo hook (owner-approved posts only, NOT yet posted): discussion 198547's best migration tooling for git deps is literally `grep -r 'git+'` — `sources` is the purpose-built answer. Same for the npm v12 migration threads.

## Where we were (v1.0.1 release notes)
- **v1.0.1 RELEASED and verified — latest on npm + GitHub.** The 0.8→1.0 arc shipped as v1.0.0 (`7063255`); **v1.0.1** is a patch fixing `audit --since` on Windows (git 8.3 short-name path mismatch caught by CI on the 1.0.0 commit). Tagged, `v1` moved to 1.0.1, GitHub Releases live for both, npm `latest` = 1.0.1, clean-room `npx` verified. **CI green on ubuntu/windows × node 20/22.** `.vsix` attached to both Releases.
- Working tree clean; everything committed. **Lesson logged: wait for CI green before `npm publish` (1.0.0 was published before CI finished and Windows caught a real `--since` bug → fixed forward in 1.0.1).**

## Shipped surfaces (all live)
- **npm**: `npm-script-lens@1.0.0` — https://www.npmjs.com/package/npm-script-lens
- **GitHub**: repo + Release `v1.0.0` (with `.vsix` asset) — Booyaka101/npm-script-lens; `v1` tag points here so the Action auto-updates.
- **CLI** (11 cmds): audit · allow · review · sync · approve · manifest · doctor · init · completion · mcp
- **4 package managers** live-verified: npm · pnpm 11 · yarn Berry 4 · bun 1.3
- **CI/local**: GitHub Action (ci-check + sync-check + v12-gaps), auto-fix bot, npm-compat + pm-compat canaries, `init --hook` + `.pre-commit-hooks.yaml`
- **Editors**: VS Code extension (`.vsix` on the Release) · Neovim plugin
- **Reporting**: Markdown · JSON · SARIF · HTML · **AI**: MCP (audit_package, audit_lockfile, classify_allowscripts)

## Still needs the owner (credential / manual gated — cannot be automated here)
1. **VS Code Marketplace publish** — needs a Marketplace PAT (Azure DevOps) for publisher `booyaka101`. Then: `cd editors/vscode && npx vsce publish` (or upload the `.vsix` at https://marketplace.visualstudio.com/manage). No `VSCE_PAT` was in the environment.
2. **GitHub Action Marketplace** — web-UI only: edit the `v1.0.0` Release → check "Publish this Action to the GitHub Marketplace" → categories Security + Dependency management. (Description already fits the 125-char limit from the v0.3.1 fix.)
3. **JetBrains plugin** — build-verified only; needs JVM/Gradle to run, not testable in this environment.
4. **Real in-editor screenshots** — run VS Code (install the `.vsix`) / Neovim once and capture, for the README Preview + Marketplace listing.
5. **Promo** (owner-approved posts only): v1.0.0 is a strong hook for community/discussions/198547, npm/rfcs#897, and the npm/cli #9562/#9463 gap threads.

## Gotchas
- npm is logged in as **`booyaka`**; gh as **`Booyaka101`**. Publishing works from this machine.
- `script-lens.policy.json` (policy) ≠ `script-lens.json` (behavior manifest) — distinct files.
- `DETECTORS.fixedInNpm` in `src/npm-contract.js` is still `null` — pin when exact fixed npm versions are known so `doctor` can retire obsolete detectors.
- `*.vsix` is now gitignored (build artifact); the canonical copy is the Release asset.
- Test count 128 includes 6 VS Code core tests auto-discovered by root `node --test`; Neovim logic tested via `editors/nvim/test/run.lua` (headless nvim, drive path `D:/…` not `/d/…`).

## Sanity check
```
node --test                # expect 129 pass
node src/cli.js --version   # 1.0.1
npm view npm-script-lens version   # 1.0.1
git status --short         # clean
```
