# Changelog

## 1.11.0 (2026-08-15)

**Provenance is an identity, not a checkbox.** Until now this tool reduced an
npm attestation to one boolean and rendered it `provenance ✓`. That check mark
earned nothing: the malicious `keyv@6.0.0` of 2026-08-04 carried a valid
attestation naming GitHub Actions as its trusted publisher, and Snyk's
teardown states the boundary precisely: *"Provenance can faithfully attest a
build whose source or workflow context has already been compromised."* This
release resolves what the attestation actually claims, the source repository,
workflow path, ref, commit and builder, and treats that identity as the thing
worth checking.

Honesty first, and it is worth being blunt: **this would not have caught
ChainDrop, and it would not have caught TanStack either.** ChainDrop published
through each project's own repository and its own release workflow, so the
attested identity matched the trusted one exactly. TanStack, three months
earlier (2026-05-11, 84 malicious versions across 42 `@tanstack/*` packages,
the first documented worm to ship validly-attested malicious packages), is
worse for us: a `pull_request_target` workflow that does not publish anything
(`bundle-size.yml`) poisoned a shared pnpm cache, `release.yml` on main
restored it, and the payload then read the OIDC token out of the runner's
memory and posted directly to the registry, bypassing the workflow's own
publish step. The
[postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
records the outcome for anyone checking identity: *"The token's attested
identity still matched `TanStack/router release.yml@refs/heads/main`."*

So neither provenance presence nor provenance identity stops this class of
attack. The defence in this tool that sits out such an event is `--cooldown`
(1.6.0), which declines to install versions younger than the window in which
worms get caught, and that window is short: TanStack's malicious versions were
spotted publicly within 20 to 26 minutes. Note also what 1.10.0's DANGEROUS
gate does **not** do here: it flags a publish path reachable from
`pull_request_target`, and TanStack's publish path was not reachable from one.
The link was a shared cache scope, not the trigger graph. That gap is real and
recorded, not papered over.

What identity resolution DOES catch is narrower: an attested repository that
disagrees with the package's declared repository, and a build identity that
moves between the version you trust and the version you are installing (a
release suddenly built by `hotfix.yml` from a branch instead of `release.yml`
from a tag).

- **`trust.provenance` is now an identity object** `{ present, repository,
  workflow, ref, commit, builder }`, read from the registry's attestation
  endpoint (the SLSA v1 predicate inside the DSSE envelope) and cached in the
  same 24h trust cache. Every surface that shows trust shows it: the audit
  report and `--json`, `review`, `audit --html`, the trust one-liner now reads
  `provenance ✓ github.com/jaredwray/keyv .github/workflows/release.yml@refs/heads/main 4a91c0e`,
  or `provenance ✓ (identity unavailable)` when the registry's answer is not a
  shape this build resolves. A `provenanceOk` boolean keeps
  `requireProvenance` and every existing consumer working. We read claims the
  registry serves over TLS, the same trust boundary as the tarball itself; no
  signatures are verified.
- **`PROVENANCE IDENTITY CHANGED`**: `diff <old> <new>` now compares the
  attested identity between versions and exits 1 (the same gate as an added
  or modified install script) when the repository, workflow path or ref moved,
  or provenance appeared or disappeared. `audit --diff`/`--since` reports the
  same fact per upgraded package, next to the capabilities-gained note,
  without changing the exit code. An identity that cannot be resolved on
  either side is never compared: enrichment failure must not manufacture a
  finding.
- **`autoApprove.expectProvenance`** in the policy file pins the identity:
  `{"keyv": "jaredwray/keyv"}` or
  `{"keyv": "jaredwray/keyv:.github/workflows/release.yml"}`. A package whose
  attestation does not match its expectation (or cannot be resolved) is never
  auto-approved, with the reason naming both the expected and the actual
  identity. Packages without an expectation are unaffected. `requireProvenance`
  keeps its old meaning, and presence alone is still not a trust signal.
- **Repo drift is an INFO note, deliberately not a detection**: when the
  attested repository names a different owner/repo than the packument declares
  (monorepo subpaths ignored), the report says so with both values, e.g.
  `provenance repo drift: package declares github.com/acme/widget, attestation
  names github.com/acme-labs/widget, likely a repo rename or transfer`. npm
  requires the declared repository to match at publish time and re-checks it
  when provenance is viewed, so a live mismatch is almost always a later
  rename or transfer. It never changes an exit code, never rises above note
  severity, and never blocks auto-approval on its own.
- **SARIF** gains `provenance-identity-changed` (warning) and
  `provenance-repo-drift` (note, never warning). **doctor** reports whether
  the registry's attestation endpoint answered.
- **Prior art, named in the README rather than talked around**: npmjs.com's
  package page already shows the build environment, source commit and build
  file; `npm audit signatures` checks signatures and attestations; and
  `cosign verify-blob-attestation --certificate-identity-regexp=...` already
  pins an expected repository and workflow **cryptographically**, which this
  release does not do. If you need cryptographic assurance for one package,
  use cosign. What those do not do is work at tree scale, across an upgrade,
  from checked-in policy.
- Every failure path is silent enrichment failure, exactly the
  osvMalicious/fetchTrust contract: a 404 is `{ present: false }`, a bundle
  with only the npm publish attestation or a malformed payload degrades to
  presence with no identity and behaves exactly as 1.10.0, and `--offline` /
  `--no-trust` issue zero attestation requests.
- Tests 350 to 366. Two pre-existing assertions were updated for the mandated
  schema change (`trust.provenance` object in a deepStrictEqual, and `diff
  --json` gaining a `provenance` key); every other pre-existing test passes
  unchanged.

## 1.10.0 (2026-08-14)

**The ChainDrop lesson: who can publish today, not just who can publish after
the cliff.** On 2026-08-04 the ChainDrop worm published 2,234 poisoned
versions across 444 npm package names by taking over a maintainer's GitHub
account and letting each project's own release workflow build, sign and
publish. Some of those releases carried valid provenance, because the
authorized build system produced them. `publish` classified such a workflow
TRUSTED and exited 0, which is true and insufficient: auth says whether the
path survives January 2027, not who can cause it to run. Registries are
already acting on this. crates.io removed `pull_request_target` and
`workflow_run` from Trusted Publishing (crates.io development update,
2026-01-21): *"Both triggers have been involved in past CI security incidents,
where attackers exploited workflow permissions to escalate access or obtain
publishing credentials."* PyPI's trusted-publisher security model names the
countermeasure: *"Dedicated environments allow for additional protections like
required reviewers, which can be used to require manual approval for a
workflow using the environment."*

- **Two new facts per resolved publish path**, alongside the auth verdict:
  `trigger` (the workflow events that reach the job, each with file:line, read
  from the top-level `on:` in all four forms: block map, flow list, scalar,
  quoted `"on":`) and `gate`, one of six classes: **DANGEROUS** (reachable
  from `pull_request_target` or `workflow_run`), **REVIEWABLE** (the job
  declares `environment:`), **MANUAL** (only `workflow_dispatch`/`release`),
  **TAG** (`push` with a tags-only filter), **AUTO** (branch push, bare push,
  schedule or pull_request with no environment), **UNKNOWN** (not
  determinable, e.g. `on: workflow_call` with no caller in this repo).
  DANGEROUS beats REVIEWABLE; otherwise the environment wins; otherwise the
  weakest trigger reached. Triggers thread through local reusable workflows
  and composite actions: a path reached via `.github/actions/release`
  inherits the calling workflow's `on:`. GitLab (`rules:`/`only:` on
  `$CI_COMMIT_TAG`, `when: manual`, `environment:`) and CircleCI (an
  approval-type job upstream in the same workflow) classify too; everything
  else stays UNKNOWN, never a guess.
- **AUTO paths get a fix ladder**: declare `environment:` with required
  reviewers (the PyPI-documented protection), or gate on
  `release: types: [published]`, or stage the publish. REVIEWABLE says
  honestly that required reviewers are a repo setting we cannot see from the
  working tree. An `if:` guard is noted, never evaluated.
- ⚠️ **`publish --check` and the Action's `publish-check` input now exit 1 on
  DANGEROUS as well as TOKEN and BROKEN.** A repo publishing from
  `pull_request_target` or `workflow_run` that passed 1.9.0 can newly fail,
  which is the point: crates.io does not accept publishes from those triggers
  at all anymore. AUTO and TAG still exit 0 unless `--require-gate
  <none|tag|manual|environment>` raises the bar (UNKNOWN never affects the
  exit code).
- **Surfaces**: the report gains `trigger:` and `gate:` lines per path (the
  only text-output change on repos without gate findings). `--json` gains
  per-path `trigger` and `gate` plus top-level `gates` counts. SARIF gains
  rules `publish-dangerous-trigger` (error, always) and `publish-ungated`
  (warning, only under `--require-gate`), both anchored to the real trigger
  line. `doctor` gains a gate-summary line. Completion learns
  `--require-gate`. The six gate classes, the banned trigger names and both
  registry quotes live in `PUBLISH.gates` in `src/npm-contract.js` and
  nowhere else.
- Tests 315 to 337. All 315 pre-existing tests pass unchanged, and the text
  output on the 19 pre-existing publish fixtures was byte-diffed against
  1.9.0: the only delta is the two new lines per path.

- **Fixed: the report told you to paste an `allowScripts` block that would
  wipe the one you have.** The suggested block is computed from the lockfile
  alone and never reads your current `allowScripts`, but the wording was
  "Paste into your `package.json`". On a project with no scripted
  dependencies that meant pasting `{"allowScripts": {}}` over a populated
  block, silently un-approving every install script the project had allowed.
  With nothing scripted there is now no JSON block at all, just a note that
  no entries are needed and that an existing block should be kept
  (`sync --check` finds stale entries). With something scripted the block
  stays, prefaced by the fact that pasting **replaces** what you have, and
  naming `allow --write` / `sync --write`, which merge and keep decisions
  you have already made. Same fix in the HTML report.
- **Fixed: `publish <path>` on a path that does not exist reported a green
  "publish paths (0)".** A mistyped directory resolved to its parent, so the
  scan ran against the wrong repo and exited 0. It now prints
  `error: no such path: <path>` and exits 2, like `audit` does for a missing
  lockfile.

**Reports now fit your terminal.** Long findings used to print as single
300-column lines that wrapped wherever the terminal happened to break them,
mid-word and against the left margin. Every text report (`audit`, `review`,
`allow`, `diff`, `sources`, `publish`, `hooks`, `doctor`) now reflows prose to
the terminal width, with continuation lines hanging under the label they
belong to. Content whose columns carry meaning is never touched: diff and
patch bodies, JSON blocks, markdown tables and aligned rows print exactly as
before.

- **Wrapping applies only when stdout is a terminal.** Piped and redirected
  output (`> report.md`, CI logs, anything parsing us) stays byte-identical to
  previous releases, so nothing downstream sees a reflowed line.
- New `src/format.js` holds the layout, with its own unit tests. Width clamps
  to 60..100 columns.

**Internals, for anyone reading the source.** `src/publish.js` had grown to
1,492 lines covering four jobs, so it is now four modules with the public API
unchanged: `publish/yaml.js` (the tolerant CI-config reader), `publish/gates.js`
(triggers and the six gate classes), `publish/report.js` (rendered report,
`--json`, SARIF, failure messages) and `publish.js` itself (scanners and
analysis), with a "where things live" map at the top. `runDoctor` went from one
180-line function to one function per check. Pure code movement: the `publish`
text output was byte-diffed across the split on all 19 fixtures and is
identical.

## 1.9.0 (2026-08-13)

**The false all-clear on trusted publishing.** A GitHub release job with
`permissions: id-token: write` and no token in the env read TRUSTED, and
`publish --check` exited 0. For a large class of real workflows that verdict is
wrong. Every `actions/setup-node` release up to and including v6 answers
`registry-url:` by writing `//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}`
into an .npmrc and exporting a dummy `NODE_AUTH_TOKEN=XXXXX-XXXXX-XXXXX-XXXXX`.
[npm/documentation#1960](https://github.com/npm/documentation/issues/1960),
open since May 2026, describes the result: *"npm CLI sees the `_authToken=`
line as 'auth is configured' and does NOT initiate the OIDC token exchange,
instead attempting a classic publish with empty credentials"*. The publish dies
with ENEEDAUTH or E404 even though the trusted publisher is configured
correctly. setup-node
[v7.0.0](https://github.com/actions/setup-node/releases/tag/v7.0.0) fixed it on
2026-07-14: *"Remove dummy NODE_AUTH_TOKEN export by @gowridurgad in
https://github.com/actions/setup-node/pull/1558"*. The trusted-publishers docs
still ship the `setup-node@v6` example with `registry-url`, so the documented
recipe is the broken one.

- **New fifth verdict `BROKEN`** (rule NPMPUB002): a TRUSTED GitHub path whose
  setup-node step resolves to v6 or older and passes a `registry-url:` for
  registry.npmjs.org. The report gives all three ways out, anchored to real
  lines: bump setup-node to v7 or later, drop `registry-url:` and run
  `npm config set registry` yourself, or
  `sed -i '/_authToken/d' "$NPM_CONFIG_USERCONFIG"` after the setup-node step.
  The npmjs.com checklist still follows, since a BROKEN path still intends
  OIDC. A ref that cannot be resolved to a version (SHA pin, branch,
  expression) gets a ⚠️ note rather than a downgrade, and the note never
  affects the exit code. GitHub Packages registries are left alone.
- ⚠️ **`publish --check` and the Action's `publish-check` input now exit 1 on
  BROKEN as well as TOKEN.** A repo that passed 1.8.0 can newly fail, which is
  the point: the old exit 0 was a clean bill of health on a publish that dies
  at the registry.
- **A pre-existing false positive, fixed first.** The `_authToken` run-line
  scanner treated any line mentioning `_authToken` as a token write, including
  the deletion line `sed -i '/_authToken/d'` recommended above. Only real
  writes count now (a redirect, `npm config set`, echo/printf/tee, an
  `_authToken=` assignment), and a job that strips the dummy line reads
  TRUSTED rather than TOKEN or BROKEN.
- **Surfaces**: `publish [dir]` also takes the directory positionally.
  `--json` gains `BROKEN` in `counts` plus per-path `setupNode` (`ref`,
  `major`, `registryUrl`, `registryLine`, `uses`, `file`, `line`) and
  `oidcNote`. `--sarif` gains rule `publish-oidc-broken` at level error.
  `doctor` reports the BROKEN count and names the setup-node ref. The
  fixed-in version, dummy token, auth line, hosts, issue links and quote all
  live in `PUBLISH.oidc` in `src/npm-contract.js` and nowhere else.
- Tests 298 to 315. `classifyAuth` is unchanged: BROKEN is a post-pass that
  only ever downgrades TRUSTED.

## 1.8.0 (2026-08-08)

**The open-time surface.** npm-script-lens already covered three moments where
code runs without the developer asking: install time (`audit`/`allow`),
resolution time (`sources`) and publish time (`publish`). The 2026-08-04 keyv
compromise added a fourth this tool was blind to: **open time**. Wiz's
teardown of that worm says it plainly: *"Persistence is attempted via Claude
Code hooks and VS Code `tasks.json`"*, two separately-hashed `setup.mjs`
payloads, one under `.claude`, one under `.vscode`. And the tarball half
predates the worm: the hijacked `html-to-gutenberg` / `fetch-page-assets`
releases (2026-05-25) shipped a hidden VS Code task named `eslint-check` with
`"runOn": "folderOpen"` inside the published package, firing when the package
directory itself is opened as a workspace. Code that runs when a folder is
*opened* never crosses an install-time gate.

- **New `hooks [dir]` command** (`--check` / `--fail-on <none|medium|high>` /
  `--json` / `--sarif [file]` / `--deps`): scans two surfaces, table-driven in
  `src/hooks.js` so adding an editor is a one-file patch,
  `.vscode/tasks.json` tasks with `runOptions.runOn: "folderOpen"` (label,
  command+args, type, and `presentation.reveal: "silent"` noted) and
  `.claude/settings.json` hooks. Auto-firing Claude events (`SessionStart`,
  `Setup`, `InstructionsLoaded`) tier at full strength; agent-triggered ones
  (`PreToolUse`, `PostToolUse`, …) are collected, tiered one level lower and
  labelled as such; the four non-command hook types (`http`, `mcp_tool`,
  `prompt`, `agent`, with `command`, the complete documented set) are
  reported but never as command execution.
- **The risk model is not forked.** Every extracted command string feeds the
  same shell-signal extraction and `score()` that `audit` applies to a
  lifecycle script: `curl … | sh`, base64 payloads, `node -e` bodies and the
  EXEC/NET binary sets are already understood, and a `node setup.mjs` whose
  file exists on disk gets that file walked too.
- **Tolerant JSONC reader** in the same spirit as the gyp lens: both files
  permit comments and trailing commas, so the parser accepts them and anchors
  every finding to a real `file:line`; a file that will not parse is reported
  `partial` (with a raw-text hint when `folderOpen` or an auto event name
  appears in the bytes), never passed silently, never a crash.
- **`--deps` scans every locked dependency's tarball** via the existing
  registry/cache path, since a folderOpen task or auto-firing hook inside a
  *package* is a shipped payload, not a team convention, so it is **HIGH
  regardless of command** (an `echo` proves nothing there), and an
  unparseable surface file inside a tarball is HIGH too. The working-tree
  scan walks monorepo subdirectories and deliberately skips `node_modules`,
  that is exactly what `--deps` covers.
- **The two surfaces are gated differently, and the caveats say so**, one
  next to each surface, never shared: a `.vscode/tasks.json` finding means
  *"this runs once you trust this folder and allow automatic tasks"* (VS Code
  1.117 defaults `task.allowAutomaticTasks` to `off` with a one-time prompt
  that does **not** display the command, microsoft/vscode#309406, and
  automatic tasks never run in an untrusted workspace); a
  `.claude/settings.json` `SessionStart` finding means *"this runs on your
  next session in this trusted folder"*, and there is no hook review gate
  (*"Claude Code doesn't use the same hook review gate as Codex"*, Datadog
  Security Labs, 2026-08).
- **Integrations:** SARIF rule `hook-auto-run` (warning; error at HIGH),
  anchored to the real file:line; opt-in `hooks-check` Action input shaped
  like `publish-check` (`::error` annotations, job-summary section, findings
  merged into the audit step's SARIF file); a `doctor` line for the open-time
  surface; shell completion knows `hooks`, `--fail-on` and `--deps`.

## 1.7.0 (2026-08-07)

**The false all-clear.** If your release job is
`- uses: ./.github/actions/release`, with the real `npm publish` and
`NODE_AUTH_TOKEN` inside `.github/actions/release/action.yml`, every
npm-script-lens release before this one reported **zero** publish paths and
`publish --check` exited 0 with *"no publish steps found in CI configs,
nothing is exposed to the token cliff"*. A clean bill of health for exactly
the workflow the GitHub changelog of 2026-07-31 is about to break: *"2FA-bypass
tokens will also lose direct publish. Their publishing surface will reduce to
reading private packages and staging a publish, which a maintainer approves
with 2FA. We are targeting January 2027 for this update."* A tool whose job is
catching the cliff must not wave through the repos that factored their release
into a composite action.

- **Local composite actions are followed.** A step's
  `uses: ./.github/actions/release` (or a pinned self-reference
  `owner/repo/path@ref` where owner/repo is this repo, with a caveat that the
  pinned ref may differ from HEAD) resolves to its `action.yml` in the working
  tree and is scanned like the job it runs in, nested local `uses:` included
  (max depth 3, cycle-guarded, never a crash: an unreadable, unparseable or
  non-composite target is one UNKNOWN, same discipline as the gyp lens).
  Third-party actions (`actions/checkout@v4`) stay silent as before.
- **Auth threads the way GitHub threads it.** Composite actions cannot declare
  `permissions`, so the id-token grant is always the calling job's. Token
  precedence, first match wins: composite step `env:` → an `_authToken` write
  in a composite `run:` line → the caller step's token-carrying `with:` entry
  → the caller's env. The common indirection is resolved end-to-end: a
  composite `env: NODE_AUTH_TOKEN: ${{ inputs.npm-token }}` is looked up in
  the calling step's `with:` map, so `with: npm-token: ${{ secrets.NPM_TOKEN }}`
  reads TOKEN, and an input the caller never resolves reads UNKNOWN, never a
  guess.
- **Local reusable workflows are scanned, not shrugged at.** A job-level
  `uses: ./.github/workflows/reusable-release.yml` used to yield UNKNOWN with
  "run npm-script-lens publish in that repo", and in that repo *is this repo*.
  The called file is now scanned with the caller's grant and `secrets: inherit`
  context, and deduplicated against its standalone scan (the caller-informed
  verdict wins).
- **`via` chains.** Every resolved path anchors to the real composite file and
  line (so `--sarif` findings resolve in code scanning) and carries the call
  chain: text output prints an indented
  `via .github/workflows/release.yml:11 (job release, step "Release")` line,
  `--json` emits `via` (empty for direct paths), and the trusted-publisher
  checklist still names the *calling* workflow's filename, which is what the
  npmjs.com form asks for.
- **Safety net for unreferenced composites.** A publishing
  `.github/actions/**/action.yml` that no scanned workflow references is
  reported once as UNKNOWN ("it may be called from another repo") instead of
  not at all. UNKNOWN still never fails `--check`, and the repo-root
  `action.yml`, the repo's own shipped Action product, is not scanned.
- `analysis.scanned` (and doctor/CLI wording) now name the
  `.github/actions/**/action.yml` surface; output for repos without local
  `uses:` references is unchanged.

## 1.6.0 (2026-08-05)

**Cooldown: stop being first.** On 2026-08-04 attackers took over the `keyv`
maintainer's GitHub account (~127M weekly npm downloads) and pushed Mini
Shai-Hulud into `keyv`, `cacheable`, `flat-cache` (565M/mo) and
`file-entry-cache` (557M/mo); the payload reached nine unrelated organisations
within roughly half an hour and over 400 packages by the end of the day. Like
every worm before it, it was identified and unpublished within hours. The
install that hurts you is the one inside that window.

Every other check in this tool asks *what does this package do?*. Cooldown
asks only *how old is this version?*, and refuses to install versions too
young to have been caught yet. It detects nothing; it declines to go first.

- **New `--cooldown [hours]` flag on `audit`** (default 72): exits 1 if any
  locked version was published less than N hours ago, listing each one with
  its age and the exact time it clears. Opt-in, no behaviour change unless
  you pass the flag.
- **New `--cooldown-allow <pkg...>`**: exempt by name (`urgent-fix`) or by
  exact version (`urgent-fix@2.0.1`), for the case where you genuinely need a
  same-day release.
- Age is computed from the absolute `publishedAt` timestamp at evaluation
  time, never from the cached `ageDays`. `fetchTrust` caches its whole result
  for 24h, so a cached `ageDays` can be a full day stale, and it errs toward
  *older*, meaning it would fail open on exactly the young package the gate
  exists to stop.
- Packages with no publish date (`--offline`, private registries) are reported
  separately as unchecked rather than blocked, so the gate stays usable in the
  setups that most want it.
- `--cooldown` widens trust enrichment to every locked package, not just the
  scripted or risky ones: a poisoned version does not need a lifecycle hook to
  hurt you, so age is needed for all of them.

## 1.5.0 (2026-08-02)

**The publish-token cliff.** npm-script-lens already prevents the
*install*-side npm v12 break in your workflows; this release covers the
*publish*-side break in the same files. The GitHub changelog of 2026-07-31
([restricting npm bypass-2FA granular access
tokens](https://github.blog/changelog/2026-07-31-restricting-npm-bypass-2fa-granular-access-tokens/))
states verbatim: *"2FA-bypass tokens will also lose direct publish. Their
publishing surface will reduce to reading private packages and staging a
publish, which a maintainer approves with 2FA. We are targeting January 2027
for this update."* Phase 1 already landed on 2026-07-31, so publishing is the
last thing a bypass-2FA token can still do, and it expires in January.

- **New `publish` command** (`--check` / `--json` / `--sarif`): pure,
  network-free analysis of `.github/workflows/*.yml`, `.gitlab-ci.yml` and
  `.circleci/config.yml` (same tolerant-reader philosophy as the gyp lens, no
  YAML dependency). Finds every publish step: `npm publish`,
  `npm stage publish`, `pnpm publish`, `yarn npm publish`, `np`,
  `semantic-release`, `changesets/action`, `JS-DevTools/npm-publish`, with
  file and line, and classifies each as exactly one of **TRUSTED** (an
  id-token grant: `permissions: id-token: write` or `write-all`; GitLab
  `id_tokens` with audience `npm:registry.npmjs.org`; CircleCI
  `NPM_ID_TOKEN`, and no token), **STAGED** (`npm stage publish`), **TOKEN**
  (`NODE_AUTH_TOKEN`/`NPM_TOKEN` in the env or an `.npmrc` write containing
  `_authToken`, with no id-token grant), or **UNKNOWN** (ambiguous, never a
  failure). Reusable workflows are UNKNOWN; `publish --check` exits 1 **only
  on TOKEN**, and a repo with no publish step passes with a one-line reason.
- **Three checks no migration blog performs**, all doc-backed:
  1. **Version floors.** docs.npmjs.com: *"Trusted publishing requires npm
     CLI version 11.5.1 or later and Node version 22.14.0 or higher"*;
     *"Staged publishing requires npm CLI version 11.15.0 or later and Node
     version 22.14.0 or higher."* The command reads `actions/setup-node`
     `node-version` and `package.json` `engines.node`, and a pin below the
     floor says exactly which fix it blocks.
  2. **Runner eligibility.** Trusted publishing supports only GitHub-hosted
     runners, GitLab.com shared runners and CircleCI cloud (*"Self-hosted
     runners are not currently supported but are planned for future
     releases."*). A `runs-on: self-hosted` (or any non-GitHub-hosted label)
     publish job gets trusted publishing marked **UNAVAILABLE** and is routed
     to the only survivable path: `npm stage publish` +
     `npm stage approve <stage-id>`.
  3. **Pre-filled npmjs.com checklist.** The trusted-publisher settings form,
     filled from the repo: org/user, repository, the workflow filename *with
     its extension*, the environment name when the job declares one, and the
     allowed actions (npm publish and/or npm stage publish).
- TOKEN paths get the concrete YAML patch (add `permissions:` /
  `id-token: write`, drop the token env) anchored to the real lines.
- **`--sarif`**: new rule `publish-token-cliff` (level error), anchored to the
  publishing workflow line. **`doctor`** gains a publish-readiness section
  (path mix + floor warnings). **GitHub Action** gains the opt-in
  `publish-check` input (default `'false'`, shaped exactly like
  `sources-check`): `::error` annotation, job-summary line, findings merged
  into the main SARIF file.
- The January-2027 date, both version floors, the provider list, the GitLab
  audience, the CircleCI variable and the full `npm stage` command set are
  registered in `src/npm-contract.js`, so every npm coupling stays in one
  file. New fixtures `publish-token` / `publish-trusted` / `publish-staged` /
  `publish-selfhosted` / `publish-oldnode` / `publish-gitlab` /
  `publish-circleci`; 245 tests, none of the new ones touch the network.

## 1.4.0 (2026-07-27)

- **VS Code extension 1.4.0** (`editors/vscode`, shipped separately to the
  Marketplace): a diagnostic is now risk × your allowlist decision, so packages
  you have already approved/denied render differently from genuinely pending
  ones. CI runs the extension's tests; the publisher preflight and allowlist
  drift gate landed in the same arc. CLI behavior unchanged (no CHANGELOG
  entry shipped at the time; recorded here retroactively).

## 1.3.0 (2026-07-27)

**The gyp lens.** Until now this tool, like every other install-script
allowlist/approval tool, only checked that `binding.gyp` *exists*, and called
the result "implicit `node-gyp rebuild`". But `binding.gyp` is not inert data:
gyp evaluates it at configure time and **runs the shell commands inside it**
(`subprocess.run(contents, shell=…)` in gyp-next's `pylib/gyp/input.py`). That
made the build file a place to hide install-time code where nobody was
looking, which is what the [June 2026 npm campaign ReversingLabs
documented](https://www.reversinglabs.com/blog/npm-bindinggyp-cicd-secrets)
(286 malicious versions across 56 packages) actually did, and what
[Aikido's 2026-06-09
teardown](https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system)
enumerated channel by channel.

- **New `src/gyp.js` reads inside `binding.gyp` and the `.gypi` files it
  includes.** GYP is not JSON: single-quoted strings, `#` comments, trailing
  commas, so it gets a tolerant reader, and a raw-text fallback that marks
  results `partial` rather than ever passing a file silently. Every channel is
  covered, taken from gyp-next's `early_variable_re` / `late_variable_re` /
  `latelate_variable_re`:
  - command expansions `<!(` `<!@(` and their late/latelate twins `>!(` `>!@(`
    `^!(` `^!@(`, the one-character evasions a naive `/<!\(/` scan misses;
  - `<!pymod_do_main(` (and `>`/`^` variants), imports a Python module and
    calls its `DoMain()`;
  - listfile expansions `<|(` `>|(` `^|(`;
  - `actions[].action`, `rules[].action`, `postbuilds[].action` build steps;
  - `make_global_settings` compiler/linker hijacks;
  - `conditions` strings reaching for the Python-eval sandbox escape
    (`__class__`/`__subclasses__`/`__import__`/`__builtins__`).
  Plain `<(var)` / `>(var)` / `^(var)` / `<@(var)` interpolation is **not**
  flagged, the true-positive/false-positive pair in one real file
  (`bufferutil`'s `<!(cc -v …)` next to its `<(clang_version)`) is a test.
- **`.gypi` files are now indexed** from the tarball and from `node_modules`
  (`--offline`), and `includes` arrays plus `deps/x.gyp:target` dependencies
  are followed one level (max 10 files, cycle-guarded). On real
  `better-sqlite3@11.10.0` this surfaces two `actions[].action` steps living in
  `deps/sqlite3.gyp`, a file the parent `binding.gyp` never shows you.
- **Wired through the whole tool**: `audit` adds `gyp: <channel> <command>`
  signals to any install-time script that reaches node-gyp (explicitly, or via
  the implicit rebuild); `gyp` scores **HIGH** alongside `exec`/`obf` and can
  be named in a policy's `denyCapabilities`; `review` prints
  `binding.gyp:5  <!( command expansion → …` above the raw lines; `--sarif`
  gains the rule `gyp-exec-channel` (level `warning`).
- **FIX: `diff` had a false negative on exactly the shape the June 2026
  wave-2 releases used.** `diff` compared `binding.gyp` by *existence*, so a
  version that **rewrote an existing** `binding.gyp` printed
  `UNCHANGED: implicit node-gyp rebuild (binding.gyp)` and exited **0**. It now
  compares contents: a rewritten build file is `MODIFIED` with a line-level
  diff and a `gainedChannels` list, and **exits 1**. `--json` gains
  `{ gyp: { changed, gainedChannels } }`. (Live: `bufferutil@4.0.8 →
  4.0.9` used to read UNCHANGED/exit 0; it now reads MODIFIED/exit 1.)
- ⚠️ **Re-baseline your manifest.** `manifest --check` baselines that contain
  native packages may now show a new `gyp` capability, because the tool sees
  something it previously could not. That is a real capability, not drift,
  re-baseline once with `npm-script-lens manifest --write` and commit the diff.

**The `v12-optional-gap` detector is now version-gated**, it was
false-positiving on every modern npm. [npm/cli#9562](https://github.com/npm/cli/issues/9562)
was closed by [PR #9597](https://github.com/npm/cli/pull/9597) (merged
2026-06-23), which skips **inert** nodes during the script-collection walk
since reify removes those dependencies before install scripts execute. It
shipped via backport #9602 in **npm 11.18.0** and is carried in **npm 12.0.0**
(2026-07-08). So on a fixed npm the detector no longer tells you to allowlist
`fsevents` on Linux: it drops optional deps whose `os`/`cpu` exclude your
platform (honoring `!`-negated entries), reading them from the lockfile entry
or the registry metadata. Optional deps that really would install here are
still reported, and on an older npm behavior is unchanged. The `fix` string and
the gaps report now state which npm was checked and the version the bug was
fixed in.

## 1.2.0 (2026-07-27)

npm v12 flips **three** defaults, not one, and this release covers the other two:
`allow-git` and `allow-remote` (both the strict enum `all`|`none`|`root`,
default `none`), under which git and remote-tarball dependencies stop
resolving entirely unless opted in.

- **New `sources` command**: finds every git (`git+ssh`/`git+https`/`git://`,
  `github:`/`gitlab:`/`bitbucket:`) and remote-tarball dependency in the
  lockfile, all four dialects: package-lock v1/v2/v3, yarn classic + berry,
  pnpm, bun.lock, and classifies each as ROOT (declared in the root
  package.json, `allow-git=root` suffices) or TRANSITIVE (forces
  `allow-git=all`, with the via-chain that drags it in). Prints the **minimal
  correct .npmrc** and, when a transitive dep forces `all`, exactly which dep
  to re-point to tighten back to `root`. Pure lockfile+config analysis, no
  network. `--json` emits `{ git, remote, npmrc }`.
- **`sources --check`** (CI gate, exit 1) fails three distinct ways:
  *insufficient* (npm v12 will refuse the install), *over-permissive* (`all`
  committed where `root` suffices, so tighten it), and *invalid*, the
  `allow-git=true` that several published migration guides recommend is not in
  the enum and npm treats it as unset. **`sources --write`** merges the
  minimal values into `.npmrc` preserving every other key, comment, and line
  byte-for-byte (npm lockfiles only, surfaced as such for yarn/pnpm/bun).
- **`allow --ci-check` now also fails** when git/remote deps exist and the
  committed config is insufficient or invalid, the same silent-CI-break shape
  as a missing allowScripts block, same fast no-scan gate.
- **`doctor`** reports git/remote dep counts, minimal values vs the committed
  `.npmrc`, whether your npm even has the keys yet (introduced in 11.10.0 /
  11.15.0, checked at full-version precision), and warns that
  `allow-git=root` is unreliable on npm 11 (npm/cli#9189, closed via PR #9206;
  root-level git deps were wrongly rejected), recommend `all` there.
- **GitHub Action `sources-check` input** (default `'false'`, opt-in): fails
  the job with an `::error` annotation and a job-summary line when the
  committed `.npmrc` doesn't match the lockfile's git/remote reality.
- New fixtures `v12-git-root`, `v12-git-transitive`, `v12-remote-tarball`;
  the audit/analyzer path is untouched (non-registry deps were and are skipped
  there), so existing reports are byte-identical. 174 tests.

## 1.1.0 (2026-07-25)

- **New `diff` command**: `npm-script-lens diff <pkg>@<old> <pkg>@<new>`
  compares the install-time lifecycle scripts (`preinstall`/`install`/
  `postinstall`) plus the implicit `node-gyp rebuild` (root `binding.gyp`)
  between two registry versions. Prints UNCHANGED (green) / ADDED (red) /
  REMOVED (yellow) / MODIFIED (red, with a line-level diff); `--json` emits
  `{ unchanged, added, removed, modified }`. Exit `1` when any script was added
  or modified (a CI gate for upgrades that grow their install surface), else
  `0`. Reuses `registry.fetchPackage` for fetching + binding.gyp detection.

## 1.0.1 (2026-07-25)

- Fix `audit --since <ref>` on Windows: resolve the base lockfile via
  `git show <ref>:./<file>` from the lockfile's directory instead of computing
  the repo-relative path host-side. The old `path.relative(toplevel, lockfile)`
  broke when git's toplevel and `os.tmpdir()` disagreed on 8.3 short names
  (e.g. `runneradmin` vs `RUNNER~1`), which git rejected as "outside
  repository." Adds a subdirectory (monorepo) regression test.

## 1.0.0 (2026-07-25)

**1.0**: npm-script-lens is now the complete, cross-ecosystem tool for the
install-script-approval problem every package manager now has, reachable from
every surface a developer works in.

- **VS Code extension** (`editors/vscode`): inline install-script risk
  diagnostics on `package.json`, a workspace status-bar summary, and commands
  to audit / generate the allowlist / review / run doctor, a thin, tested UI
  over the CLI engine. Ships a Marketplace-ready icon + gallery banner and a
  Getting-Started **walkthrough** (audit → allowlist → CI); packaged and
  installable (`.vsix`).
- **`sync-check` Action input**: fails the job when the install-script allowlist
  has drifted from the lockfile, cross-ecosystem (npm/pnpm/yarn/bun,
  auto-detected), a stronger companion to `ci-check`.
- **Neovim plugin** (`editors/nvim`): `vim.diagnostic` install-script risk on
  `package.json` + `:NpmScriptLens*` commands; verified loading under headless
  Neovim 0.12.
- **Shareable HTML report**: `audit --html report.html` writes a self-contained,
  script-free dashboard (risk summary, per-package table, allowlist block).
- **Shell completions**: `npm-script-lens completion <bash|zsh|fish>`.
- **Local enforcement**: `init --hook` installs a git pre-commit hook running
  `sync --check`, and the repo ships a `.pre-commit-hooks.yaml` for the
  pre-commit framework.
- The full workflow, **`audit` · `allow` · `review` · `sync` · `approve` ·
  `manifest` · `doctor` · `init`**, works across **npm, pnpm, yarn Berry, and
  bun**, all four verified end-to-end against the real binary, each writing its
  native allowlist (`allowScripts` / `allowBuilds` / `dependenciesMeta` /
  `trustedDependencies`).
- **Governance** (`script-lens.policy.json`): risk ceiling, capability bans,
  age/provenance requirements (trust-enriched for every candidate), and
  per-package waivers with expiry.
- **CI**: `allow --ci-check`, `sync --check`, a GitHub Action, an auto-fix bot
  workflow (`init --auto-fix`), and two self-drift canaries (npm-compat,
  pm-compat).
- **Durability**: a centralized manager contract (`npm-contract` +
  `pm-contract`) and a `doctor` that fails on drift, so the tool stays correct
  as npm/pnpm/yarn/bun evolve.
- **AI agents**: MCP server with `audit_package`, `audit_lockfile`, and
  `classify_allowscripts`.

Reaching 1.0 from the v0.5 release spanned: cross-ecosystem allow/review/sync,
policy, init, doctor, `--since`, the MCP allow tool, the canaries, and the
editor extension. 124 tests.

## 0.12.0 (2026-07-25)

- **Auto-fix bot**: `init --auto-fix` scaffolds a workflow that, on
  Renovate/Dependabot branches, runs `sync --write` and commits the reconciled
  allowlist back, so a dependency bump can't silently leave the branch with an
  uninstallable allowlist.
- **Policy age/provenance now enforce for every package**: a policy with
  `minAgeDays` or `requireProvenance` triggers trust enrichment for *all*
  scripted packages (previously only HIGH/MEDIUM had trust data), so those
  rules work on LOW packages too. With `--no-trust` the rules fail closed (an
  unverifiable package is held for review, never auto-approved).

## 0.11.0 (2026-07-25)

The whole workflow is cross-ecosystem, governable, and one command to adopt.

- **`review` and `sync` now speak every package manager**, joining `allow`.
  They auto-detect the manager, read its existing native allowlist for
  coverage, and write decisions back in the right format/file (npm
  `allowScripts` · pnpm `allowBuilds` · yarn `dependenciesMeta.built` · bun
  `trustedDependencies`). `--manager` overrides detection on all three.
- **All four managers are now verified end-to-end against the real binary**
  (npm, pnpm 11, yarn Berry 4, bun 1.3): `allow --write` generates the native
  allowlist and the manager then runs a previously-blocked install script.
- **Governance policy** (`script-lens.policy.json`, or `--policy <file>`):
  codify what auto-approves instead of the fixed SAFE/LOW heuristic,
  `autoApprove.maxRisk`, `denyCapabilities` (never auto-approve a given
  exec/net/fs/… capability), `minAgeDays` and `requireProvenance` (need trust
  data), and per-package `waivers` with a reason and an `expires` date. With no
  policy file, behavior is exactly the built-in default. Honored by `allow`,
  `review`, and `sync`.
- **`init`**: scaffolds `script-lens.policy.json` + a ready-to-commit CI
  workflow (audit + `allow --ci-check` gate) in one command; skips existing
  files unless `--force`.
- **`classify_allowscripts` MCP tool** and the CLI share one decision engine,
  so agents get the same policy-aware split.
- **pm-compat canary** (`.github/workflows/pm-compat.yml`): a scheduled matrix
  (npm/pnpm/bun) that drives each real manager through `allow --write` and
  asserts the approved script runs, the cross-ecosystem drift tripwire.
- **`src/pm-contract.js`** gained `readExisting`/`covers` (coverage),
  `writeDecisions` (true/false where the format allows) and `writeFull`
  (replace, so `sync` can drop stale entries) per manager.

## 0.10.0 (2026-07-24)

Cross-ecosystem release: install-script approval isn't an npm-only problem
anymore, so `allow` isn't npm-only anymore.

- **`allow` now speaks every major package manager's native allowlist**, auto-
  detected from the lockfile:
  - **npm** → `allowScripts` (`"pkg@1.2.3": true`) in package.json
  - **pnpm** → `allowBuilds` (`pkg: true`) in pnpm-workspace.yaml (pnpm ≥ 10.26
    / v11; older pnpm 10 uses the `onlyBuiltDependencies` array)
  - **yarn Berry** → `dependenciesMeta.<pkg>.built: true` in package.json
    (+ `enableScripts: false` in .yarnrc.yml)
  - **bun** → `trustedDependencies: ["pkg"]` in package.json
  The same SAFE/LOW→approve, MEDIUM/HIGH/malicious→`_review` policy and the same
  behavioral analysis drive all four; only the emitted format differs. stdout is
  the manager's native block, directly pasteable.
- **`allow --write`** merges the auto-approved entries into the right file for
  the detected manager (package.json / pnpm-workspace.yaml / .yarnrc.yml),
  preserving everything else. The pnpm-workspace.yaml merge is comment- and
  key-preserving with no YAML dependency.
- **`allow --manager <npm|pnpm|yarn|bun>`** overrides auto-detection.
- **Safety notes surfaced**: bun's `trustedDependencies` *replaces* bun's built-
  in trusted list (so default-trusted scripted deps can be dropped), `allow`
  warns; yarn needs `enableScripts: false` to be an allowlist, and `allow --write`
  sets it.
- **`doctor`** now reports the detected package manager and which allowlist file
  `allow` will target.
- **`src/pm-contract.js`**: one adapter per manager (detect / key / render /
  write), so adding or tracking a manager's format is a single-file change.
- Verified end-to-end against **real pnpm 11**: `allow --write` generated a
  `pnpm-workspace.yaml` that pnpm accepted and used to run an approved package's
  install script. npm is likewise live-verified; yarn/bun formats are verified
  against their official docs and unit-tested (those binaries weren't installed
  in the build environment).

## 0.9.0 (2026-07-24)

Durability release: keeping the tool useful as npm itself changes.

- **`doctor` command**: probes your local npm and reports, check by check,
  whether the npm contract this build assumes still holds: npm version,
  allowScripts enforcement, a parser self-test against the canonical dry-run
  shapes, a live `npm install --dry-run --json` shape check, the assumed
  contract, and each detector's upstream status. Exits 1 on genuine drift (an
  unrecognized output shape). `--json` for machine output; `--no-live`/
  `--offline` skip the live probe.
- **Loud drift detection**: `review` no longer silently treats an unfamiliar
  npm output as "nothing pending". A v12+ npm whose `--dry-run --json` shape
  isn't recognized now warns and falls back to the lockfile, pointing at
  `doctor`.
- **npm-compat canary** (`.github/workflows/npm-compat.yml` +
  `scripts/npm-compat-canary.js`): a scheduled matrix over npm `12`/`latest`/
  `next` that drives the **real** npm (not the test stubs) against a scratch
  project and fails on drift, the automated tripwire the unit tests can't be.
- **Centralized npm contract** (`src/npm-contract.js`): every npm coupling,
  field name, version threshold, dry-run args, `unreviewedScripts` key, summary
  keys, command/flag names, and the detector upstream-status table, lives in
  one file, so a future npm change is a one-file patch.
- **Version-aware v12 gap detectors**: the gap report now states which local
  npm it checked against, and each finding carries its upstream issue and fix
  status (e.g. npm/cli#9463's fix landing in `c14e87c`).
- **`audit --since <git-ref>`**: like `--diff`, but extracts the base lockfile
  from a git ref (branch/tag/SHA) automatically, auditing only what changed since
  then, ideal for Renovate/Dependabot branches.
- **`classify_allowscripts` MCP tool**: agents can get the `allow` split
  (`{allowScripts, _review}`) non-interactively over the existing MCP server.

## 0.8.0 (2026-07-24)

- **`allow` subcommand**: one-shot split of every package with install-time
  scripts into a pre-approved `allowScripts` block (behavioral risk SAFE/LOW,
  not known-malicious) and a `_review` list (MEDIUM/HIGH, known-malicious, or
  un-fetchable). Emits `{ "allowScripts": { … }, "_review": [ … ] }` as JSON on
  stdout and an `X packages auto-approved, Y need manual review.` summary on
  stderr. `--input <audit.json>` classifies a saved `audit --json` result
  instead of re-running the scan. `--write` merges the auto-approved entries
  into `package.json` (preserving existing keys); `_review` packages are left
  out so a human still decides on them.
- **`allow --ci-check`**: a fast CI guard (no scan) that exits `1` when a
  workflow in `.github/workflows/` runs `npm install`/`i`/`ci`, `package.json`
  has no `allowScripts` block, and the local npm is v12+ (probed via
  `npm --version`), the exact combination where npm v12 silently skips every
  dependency's install scripts. Passes with a one-line reason otherwise.
- **GitHub Action `ci-check` input** (default `'false'`, opt-in): runs the
  `allow --ci-check` gate as a fail-fast composite step (`if: always()`), so the
  same npm-v12 break check fails the job with a `::error` annotation and a job
  summary line. Shares one detection function with the CLI (`ciCheckResult`).

## 0.7.0 (2026-07-24)

- **`review` subcommand**: lists packages with pending npm v12 approve-scripts
  approvals alongside the actual install-script content, so you can see exactly
  what each lifecycle script would run before allowing it.

## 0.6.0 (2026-07-23)

- **npm v12 approve-scripts gap check** (`audit --check-v12-gaps`, Action
  input `check-v12-gaps`): detects the two known bugs in npm v12's
  approve-scripts tooling.
  - `v12-optional-gap` ([npm/cli#9562](https://github.com/npm/cli/issues/9562)):
    optional dependencies with install scripts that
    `npm approve-scripts --allow-scripts-pending` never surfaces but
    `npm ci --strict-allow-scripts` rejects (the fsevents-on-Linux trap).
    Reads `optional`/`hasInstallScript` from package-lock.json, resolves
    script names from registry metadata, and reports any such package missing
    from `allowScripts` (bare-name and version-pinned keys both count).
  - `v12-eglobal-risk` ([npm/cli#9463](https://github.com/npm/cli/issues/9463)):
    `npm install -g <pkg>` lines in `.github/workflows/*.yml` where the
    package has install scripts (per registry metadata) and no
    `--allow-scripts`, and there is no post-install approval path in global
    contexts (`approve-scripts` errors EGLOBAL), so the fix is inline:
    `npm install -g --allow-scripts=<pkg> <pkg>`.
  - Findings are severity `warn` (exit 0) and integrate with the existing
    output surfaces: Markdown report, `--json` (`{ findings: [...] }`), and
    `--sarif` (new rules `v12-optional-gap` / `v12-eglobal-risk`, results
    anchored to the lockfile or workflow line).
  - In the Action, the check runs as a separate step gated on the runner's
    npm major version (`check-v12-gaps: auto` runs it when npm is v12+;
    `true`/`false` force). It writes to the job summary, annotates via
    `::warning`, and merges its findings into the SARIF file the audit step
    wrote.

## 0.5.0 (2026-07-21)

- **`manifest` command**: writes a stable, committable receipt of install-time
  behavior (`script-lens.json`), sorted `name@version` → capability kinds,
  so the git diff of that file is the approval-surface change, reviewable with
  no tooling. `--check` fails CI on drift with a human-readable diff; the
  Action gains a `manifest-check` input that reports drift to the job summary.
  Behavior-only and deterministic (no trust/OSV data), so it changes when
  capabilities change, not popularity. Closes #1 (thanks @raju_dandigam).

## 0.4.0 (2026-07-21)

- **Cross-package bin resolution**: `husky install`-style scripts are no
  longer conservatively HIGH: when a lockfile package with the same name
  owns the bin, its actual bin script is fetched, analyzed, and the row is
  re-scored on real evidence (`bin: husky install → husky@9.1.7`).
- **Payload decoding**: base64 / char-code / eval'd **literal** payloads are
  decoded and re-analyzed, so the report shows what hidden code actually
  does. Runtime-assembled payloads remain flagged-but-opaque.
- **`--deep`** (CLI + Action input `deep`): follow bare `require()`s from
  install-script code into the matching lockfile package's entry file, one
  level deep, closing the curated-helper-list gap for in-tree helpers.

## 0.3.1 (2026-07-21)

- Shorten the Action description to fit the GitHub Marketplace 125-character
  limit. No functional changes.

## 0.3.0 (2026-07-21)

- **Behavioral upgrade diff**: in `--diff` mode, packages that changed version
  are compared against the base version's analysis and the report calls out
  **capabilities the upgrade gained**, the fingerprint of a hijacked release.
- **`sync` command**: reconcile the `allowScripts` block in package.json with
  the lockfile. Stale entries dropped, upgrades re-pinned (previous decisions
  preserved when nothing was gained, flagged for re-review otherwise), new
  packages added. `--write` applies, `--check` gates CI.
- **`approve` command**: interactive, evidence-driven approval, stepping through
  risky packages and writes decisions to package.json.
- **Trust context**: risky packages are enriched with publish age, weekly
  downloads, maintainer count, and sigstore provenance; every audited package
  is checked against OSV, and `MAL-*` advisories render as ⛔ KNOWN MALICIOUS,
  always `false` in allowScripts, and fail `--fail-on-high`.
- **Via chains**: reports show how a package entered the tree
  (`via prisma → @prisma/engines`), derived from lockfile dependency edges in
  all supported formats.
- **`--offline`**: analyze packages from `node_modules` on disk, air-gapped
  audits, zero network.
- **`bun.lock` support** (text lockfile; JSONC tolerated).
- **MCP server** (`npm-script-lens mcp`): stdio server with `audit_package`
  and `audit_lockfile` tools so AI coding agents can audit a package before
  adding it as a dependency.

## 0.2.0 (2026-07-21)

- **yarn and pnpm lockfiles**: `yarn.lock` (classic v1 and berry) and
  `pnpm-lock.yaml` (v5/v6/v9 formats) are parsed alongside
  `package-lock.json`/`npm-shrinkwrap.json`; directories are searched for all
  four. Non-registry entries (`file:`/`link:`/`workspace:`/`patch:`/git) are
  skipped, classic-yarn `npm:` aliases resolve to the real package.
- **Obfuscation detection** (new `obf:` signal class, scores HIGH): `eval()`,
  `new Function()`, `vm`, string-built `require()` specifiers (concatenation /
  template interpolation), `atob`/`Buffer.from(…, 'base64')` decoding, and
  bulk `String.fromCharCode` payload building.
- **`--diff <base-lockfile>`**: audit only packages added or upgraded relative
  to a base lockfile, built for PR workflows (also an Action input,
  `diff-base`).
- **`--sarif <file>`**: SARIF 2.1.0 output for GitHub code scanning, results
  anchored to the package's line in the lockfile (Action input `sarif-file`).
- **On-disk result cache** keyed `name@version` + tool version (published
  tarballs are immutable); repeat audits skip the network entirely.
  `--no-cache` disables, `NPM_SCRIPT_LENS_CACHE_DIR` relocates.
- Action `path` input now defaults to `.` and auto-detects the lockfile type.

## 0.1.0 (2026-07-21)

Initial release.

- `audit` command: registry fetch → in-memory tarball index → static analysis
  of `preinstall`/`install`/`postinstall` scripts and the JS files they run
  (relative `require`/`import` chains, `node -e` bodies,
  `path.join(__dirname, …)` indirections, `npm run` recursion; depth ≤ 3).
- Risk ladder HIGH (exec) / MEDIUM (network) / LOW (fs/env) / SAFE, with a
  version-pinned `allowScripts` suggestion block per npm v12.
- Implicit `node-gyp rebuild` detection for packages shipping a root
  `binding.gyp` with no install script.
- Composite GitHub Action: job summary, PR comment, `fail-on-high` gate.
