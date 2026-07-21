# PROGRESS — npm-script-lens

**State: v0.3.0 RELEASED (2026-07-21, owner go-ahead) — 51/51 tests pass. GitHub: Booyaka101/npm-script-lens, tags v0.2.0 / v0.3.0, `v1` moved to the 0.3.0 commit, GitHub Release published. npm publish still pending owner login.**

## v0.3.0 features (all tested, 2026-07-21)
- **Behavioral upgrade diff**: `--diff` compares upgraded packages against the base version's rows → `base: {version, gained}` per result; report renders "⚠️ gained vs X" / "no new capabilities". The hijacked-release detector.
- **`sync`**: reconciles package.json allowScripts vs lockfile — stale dropped, upgrades re-pinned (decision preserved iff gained nothing, else risk default + re-review flag), new added; `--write` / `--check`.
- **`approve`**: interactive readline flow, evidence per package, writes decisions.
- **Trust** (src/trust.js): OSV querybatch for ALL audited packages (MAL-* → r.malicious, ⛔ badge, forced false, fails the gate); packument age/maintainers/provenance + downloads for HIGH/MEDIUM only; 24h-TTL disk cache; env-overridable endpoints (NPM_SCRIPT_LENS_OSV_API / _DL_API) for tests.
- **Via chains**: name-level dependency edges from ALL lockfile parsers; viaChain BFS climbs to a parentless package (cycle-safe — dead-end fallback tested).
- **`--offline`**: loadLocalPackage indexes node_modules dirs (npm lockKey → exact nested path); implies no-trust.
- **bun.lock**: JSONC-tolerant parser (custom stripJsonc); bun.lockb detected → helpful error.
- **MCP server** (src/mcp.js): hand-rolled newline-JSON-RPC stdio, tools audit_package (resolves latest when version omitted; verdict line) + audit_lockfile.
- Gotchas fixed en route: pnpm entry regex must anchor `[^\s'"]` first char or `dependencies:` lines swallow entryName; npm lockKey dedup must keep FIRST (shallowest) occurrence; `.get()` on a require() call expression has no receiver name → signal is `net: require('https')`, not `net: https.get`.

## Phase 0 verification (all passed, 2026-07-21)
- `https://registry.npmjs.org/sharp` — public JSON, per-version `scripts` + `dist.tarball`. ✔
- `npm/rfcs#897` — open RRFC "allowScripts Review Report" (it's an issue, not a PR; same content the brief described). ✔
- github.blog changelog 2026-07-08 — npm v12 GA, lifecycle scripts + implicit node-gyp opt-in via `allowScripts`, managed by `npm approve-scripts`; entries are version-pinned `"pkg@1.2.3": true`, `false` = deny. ✔
- Cost model: public registry only, zero paid resources. ✔ npm name `npm-script-lens` unclaimed (404). ✔

## VERIFIED working — 42/42 tests pass (`node --test`, ~8s, mixes offline mocks + live registry)
- **Acceptance (1)** sharp@0.33.5 → HIGH, signal `exec: node-gyp rebuild --directory=src` (via tarball chain `install/check.js` → `../lib/libvips`). ✔
- **Acceptance (2)** chalk@5.3.0 → SAFE. ✔
- **Acceptance (3)** documented deviation: prisma@5's own preinstall is a version check (LOW); the network capability is correctly caught on its dep @prisma/engines (`net: require('@prisma/fetch-engine')`), scored HIGH because the chain also spawns (execa). Notably prisma stayed LOW after the obfuscation pass — no false positives on real bundled code. ✔
- **Acceptance (4)** action exits 1 on fail-on-high + HIGH dep; PR comment POST verified against a local mock GitHub API; job summary written; SARIF file written with error-level results. ✔
- **Acceptance (5)** allowScripts block JSON.parse-able (asserted in 4 places incl. the real PR-comment body). ✔
- **CLI e2e** (spawned processes): exit 0/1/2 paths; --json; --out; --diff/--sarif/--no-cache combined run against offline mock registry; sample report auto-synced by test.
- **Offline mock-registry suites**: implicit `node-gyp rebuild` synthesis, no-scripts tarball skip, tarball package.json override, 404-is-final; cache hit/miss/disable semantics (zero requests on cached run asserted); diff-mode subsetting.
- **Scale/variety fixture** (12 real script-heavy packages): zero fetch errors, ≥3 HIGH, husky/nan/ws SAFE, core-js LOW.
- **npm pack** contents asserted by test: ships src/, action.yml, README, LICENSE; no test/fixtures/dev files.

## v0.2.0 features (all covered by tests, 2026-07-21)
- **Multi-lockfile**: yarn.lock classic (multi-selector entries, `npm:` aliases, file/git skipped) + berry (`resolution:`-based, npm: protocol only); pnpm-lock.yaml v5 (`/name/1.2.3_peer@2.0.0` — the `_peer@` suffix contains `@`, stripped before the split), v6 (`/name@1.2.3(peer)`), v9 (`name@1.2.3`). Directory search order: package-lock.json → npm-shrinkwrap.json → yarn.lock → pnpm-lock.yaml. Parsing lives in src/lockfiles.js.
- **Obfuscation signals** (`obf:` class → HIGH): eval, Function constructor (new + call), vm module, string-built require specifiers (BinaryExpression / TemplateLiteral-with-expressions only — plain identifier args deliberately NOT flagged, that's bundler/binding-loader idiom and broke nothing live), atob / Buffer.from(…, 'base64'), String.fromCharCode with ≥8 args.
- **--diff BASE** (CLI) / `diff-base` (Action): audit only name@version pairs absent from the base lockfile; report carries a diff-mode note line.
- **--sarif FILE** (CLI) / `sarif-file` (Action): SARIF 2.1.0, rules per risk tier, HIGH→error MEDIUM→warning LOW/ERROR→note, results anchored to the package's lockfile line, stable partialFingerprints.
- **Disk cache** (src/cache.js): keyed name@version + tool version, default on, `--no-cache` / `NPM_SCRIPT_LENS_CACHE_DIR`; errors not cached; best-effort writes.
- Action `path` default changed `package-lock.json` → `.` (auto-detects lockfile type).

## Hardening from pass 2 (still in place, all tested)
- Quote-aware shell splitting; env-var prefixes and `cross-env` unwrapped; `npx` = exec+net; `-p/--print` eval bodies; `npm/yarn/pnpm run` recursion (cycle-safe); ESM import forms; `prepare` excluded from audited lifecycle; registry timeouts/one-retry/404-final; PR comment 60k truncation; CI (ubuntu+windows × node 20/22) + self-audit dogfood workflows.

## Publish state (2026-07-21)
- `npm whoami` → **401, not logged in**. Owner must `npm login` then `npm publish` (pack-verified; name free as of 2026-07-21).
- Hosting account decided by owner (2026-07-21): **Booyaka101** — all repo URLs updated; repo created public, pushed, tagged `v0.2.0` + `v1`.

## Next steps (owner actions)
1. `npm login` + `npm publish`.
2. Push to the chosen GitHub account, tag `v1` → Action usable; ci.yml + self-audit.yml activate.
3. Post the sample report in npm/rfcs#897 + GitHub community discussion #198547 (npm v12 migration) — the distribution wedge.
4. v0.3 ideas: SARIF `--diff` fingerprint stability across lockfile moves, workspaces-aware allowScripts placement, watch mode for Dependabot branches.
