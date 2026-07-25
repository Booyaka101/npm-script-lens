# ▶️ RESUME — npm-script-lens

_Updated 2026-07-25 after the v1.0.0 release._

## Where we are
- **v1.0.0 RELEASED and verified.** Committed + pushed (`7063255`), tagged `v1.0.0`, `v1` moved to it, **GitHub Release live**, **published to npm** (`npm-script-lens@1.0.0`, `latest`), clean-room `npx` smoke passed. The `.vsix` is attached to the GitHub Release (installable via "Install from VSIX").
- Working tree is now clean of the old 0.8→1.0 backlog — everything is committed.

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
node --test                # expect 128 pass
node src/cli.js --version   # 1.0.0
npm view npm-script-lens version   # 1.0.0
git status --short         # clean
```
