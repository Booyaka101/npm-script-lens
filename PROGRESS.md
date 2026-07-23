# PROGRESS — npm-script-lens

**State: v0.6.0 BUILT locally (2026-07-23) — 62/62 tests pass. Committed locally, NOT pushed (this session's brief forbids external publishing; owner pushes/tags/releases). Prior released state: v0.5.0 on npm + GitHub (Booyaka101/npm-script-lens, `v1` tag).**

## v0.6.0 — npm v12 approve-scripts gap check (2026-07-23, all tested)
- **src/v12gaps.js**: two detectors for npm v12's own tooling bugs.
  - `checkOptionalGap` (npm/cli#9562, closed via cli PR #9597 upstream but present in the wild): optional lockfile entries (`optional: true`) with install scripts, missing from `allowScripts` (bare-name AND `name@version` keys count; `false` counts as a decision). `hasInstallScript` from the lock is authoritative in v2/v3 (false ⇒ skip, no fetch); script NAMES come from registry version metadata; registry-unreachable + lockfile-says-scripted still warns with an honest label. npm lockfiles only (the bug is npm's).
  - `checkEglobal` (npm/cli#9463, closed-not-planned upstream — the trap stays): `npm install|i|add … -g/--global/--location=global` lines in `.github/workflows/*.y(a)ml`, package has install scripts per registry (`/pkg/<exact-ver-or-latest>`), no `--allow-scripts`/`--ignore-scripts` on the command ⇒ finding anchored to file:line. Quote-stripped tokens, value-flag skipping (`--registry x` etc.), shell-separator-aware (`&&`, `;`, `#`…), URL/path specs skipped, unknown-on-registry skipped (no guessing).
- **Wiring**: `audit --check-v12-gaps` runs ONLY these checks → `buildGapsReport` markdown / `--json` `{findings}` / `--sarif` (rules `v12-optional-gap` + `v12-eglobal-risk` now always in the driver rules; findings level `warning`, anchored to lockfile or workflow line, fingerprint `gap:<id>:<pkg>`). Severity warn ⇒ always exit 0.
- **Action**: new input `check-v12-gaps` (default `auto`), separate composite step with `if: always()` that gates on `npm --version` major ≥ 12 (or `true` forces), runs `node src/action.js v12-gaps` → job summary + `::warning` per finding + merges results/rules into the SARIF file the audit step wrote (dedup by rule id).
- **Fixtures**: `fixtures/v12-optional-gap` (gap-opt = finding, covered-opt = allowScripts-covered, clean-opt = no script ⇒ never fetched, ghost-opt = registry-404 fallback, plainpkg = non-optional control) and `fixtures/v12-eglobal` (workflow with scripted/clean/guarded/unknown/non-global/implicit-gyp/multi-command lines).
- **Tests**: test/v12gaps.test.js — 7 tests (unit + CLI e2e + action e2e w/ SARIF merge) against a mock registry; full suite 62/62 in ~4s.
- **Real-data verification (live registry, 2026-07-23)**: chokidar@3 project (`npm i --package-lock-only`) → `fsevents@2.3.3` optional-gap finding (the literal package from #9562); workflow `npm install -g sharp@0.33.5` → eglobal finding at deploy.yml:7. Also verified sharp@0.35.3 (latest) dropped its install script ⇒ correctly NOT flagged.
- **Phase 0 re-verification (2026-07-23)**: github.com/blog changelog URL 404s → canonical is github.blog (2026-06-09 post confirmed: allowScripts off by default in v12, approve-scripts/deny-scripts, allow-scripts config for global/npx). #9562 CLOSED w/ PR #9597; #9463 CLOSED as not planned (flag-at-install-time is the sanctioned path — our fix text matches). Zero paid resources.
- **Second-pass re-verification (2026-07-23, later session with the same brief)**: all Phase 0 URLs re-fetched and confirmed; 62/62 tests re-run green; real-data e2e re-run live (fresh `npm i --package-lock-only` chokidar project → fsevents@2.3.3 optional-gap finding; `npm install -g sharp@0.33.5` workflow → eglobal finding at deploy.yml:6). No code changes needed — the brief was already fully shipped as v0.6.0 at commit 2057f2d.
- Version bumped to 0.6.0; committed manifest `script-lens.json` regenerated (it embeds the tool version — regenerate on every bump or self-audit manifest-check fails).

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

## Distribution (2026-07-21, all done except Marketplace)
- npm-script-lens@0.3.0 published to npm by owner; registry install verified end-to-end.
- Promo posted (owner-approved, from Booyaka101):
  - npm/rfcs#897 → https://github.com/npm/rfcs/issues/897#issuecomment-5034525452 (framed as prior art for the first-party approve-scripts report; RRFC author vbjay has a competing/complementary npm-cli PR — watch for replies)
  - community discussion → https://github.com/community/community/discussions/198547#discussioncomment-17717113
- GitHub Marketplace listing: WEB-UI ONLY, owner must click — edit release v0.3.0 → check "Publish this Action to the GitHub Marketplace" → accept dev agreement (first time) → categories Security + Dependency management. action.yml already meets requirements (unique name, description, branding search/red). Requires 2FA on the account.

## Next steps
1. Owner: push v0.6.0 (`git push`), tag `v0.6.0`, move `v1` to it, GitHub Release, `npm publish` (logged-in), Marketplace click-through if still pending.
2. Distribution idea for 0.6.0: comment on npm/cli#9562/#9463 threads that npm-script-lens now detects both gaps pre-CI (owner-approved posts only).
3. v0.7 ideas: workspaces-aware allowScripts placement, Dependabot-branch watch mode, SARIF fingerprint stability across lockfile moves.
