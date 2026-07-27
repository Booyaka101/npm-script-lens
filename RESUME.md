# ▶️ RESUME — npm-script-lens

_Updated 2026-07-27 after building v1.2.0 (local, unpublished)._

## v1.2.0 — ready to ship (owner: push, tag, `npm publish` after CI green)
- **New `sources` command** covers npm v12's other two flipped defaults, `allow-git`/`allow-remote` (enum `all|none|root`, default `none`): finds git + remote-tarball deps in all four lockfile dialects, classifies ROOT vs TRANSITIVE (transitive forces `all`), prints/writes the minimal correct `.npmrc` (comment-preserving), `--check` fails on insufficient / over-permissive / invalid (`=true`) config. `allow --ci-check`, `doctor`, and the Action (`sources-check` input) extended. 174/174 tests. See PROGRESS.md → v1.2.0.
- Ship steps: `git push` → wait CI green (lesson from 1.0.0!) → tag `v1.2.0`, move `v1` → GitHub Release → `npm publish`.
- Promo hook: discussion 198547's best migration tooling for git deps is literally `grep -r 'git+'` — `sources` is the purpose-built answer (owner-approved posts only).

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
