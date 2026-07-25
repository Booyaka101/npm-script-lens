# ⏸️ RESUME HERE — continue tomorrow

_Note left 2026-07-25. Read `PROGRESS.md` for full detail; this is the quick pick-up._

## Where we are
- **v1.0.0 built locally — 128/128 JS tests pass.** Everything from v0.6.0 → 1.0.0 is **one uncommitted working tree**. Nothing has been committed, pushed, or published this arc.
- Last released state: **v0.5.0** on npm + GitHub (`Booyaka101/npm-script-lens`, `v1` tag).

## What's done & verified (all surfaces)
- **CLI** (11 cmds): audit · allow · review · sync · approve · manifest · doctor · init · completion · mcp
- **4 package managers** live-verified end-to-end: npm · pnpm 11 · yarn Berry 4 · bun 1.3 (allow/review/sync write each native allowlist)
- **Governance**: `script-lens.policy.json` (maxRisk / denyCapabilities / minAgeDays / requireProvenance / waivers), trust-enriched for all pkgs
- **CI**: GitHub Action (`ci-check` + cross-PM `sync-check`), auto-fix bot (`init --auto-fix`), 2 drift canaries (npm-compat, pm-compat)
- **Local**: `init --hook` git pre-commit + `.pre-commit-hooks.yaml`
- **Editors**: VS Code (`editors/vscode`, icon + walkthrough, `.vsix`-verified) · Neovim (`editors/nvim`, headless-verified on 0.12.2)
- **Reporting**: Markdown · JSON · SARIF · HTML (`audit --html`)
- **AI**: MCP server (`audit_package`, `audit_lockfile`, `classify_allowscripts`)

## Pick up here (options offered, user to choose)
1. **Release checklist / one-shot publish script** — so owner ships it all in a few commands: `git` commit+push+tag `v1.0.0`, GitHub Release, `npm publish`, `cd editors/vscode && vsce publish`, GitHub Action Marketplace click-through.
2. **JetBrains plugin** — build-verified but NOT runtime-testable here (needs JVM/Gradle).
3. **Real in-editor screenshots** — needs the owner to run VS Code/Neovim once and send them back (can't capture headless).
4. Anything new the owner wants.

## Gotchas to remember
- **Owner does all publishing** — this session's brief forbids commit/push/publish; leave the tree uncommitted.
- Global `yarn` (via corepack) + `bun` (via npm) were installed on this machine during verification.
- Neovim on Windows needs a **drive path** (`D:/…`), not git-bash `/d/…`.
- `script-lens.policy.json` (policy) ≠ `script-lens.json` (behavior manifest) — distinct files.
- `DETECTORS.fixedInNpm` in `src/npm-contract.js` is still `null` (pin when exact fixed npm versions are known → doctor can auto-retire obsolete detectors).
- Test count includes 6 VS Code core tests auto-discovered by root `node --test`; Neovim logic tested via `editors/nvim/test/run.lua` (headless nvim, not node).

## Sanity check before resuming
```
node --test                      # expect 128 pass
node src/cli.js --version         # 1.0.0
git status --short                # confirm still uncommitted
```
