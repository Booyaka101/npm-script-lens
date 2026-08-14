# Changelog

## 1.8.1

Listing metadata only. No functional change.

The extension shells out to the CLI, so users already had the CLI's provenance
identity work from 1.11.0 without updating anything here. The Marketplace
listing just never said so, and neither the description nor the keywords
mentioned provenance, attestation or approve-scripts, which is how people
search for this.

## 1.8.0

**Diagnostics on the open-time surface.** The 2026-08-04 keyv worm persisted
via exactly two files this editor shows you every day — Wiz: *"Persistence is
attempted via Claude Code hooks and VS Code `tasks.json`"*. The extension now
scans them where you read them:

- **Inline diagnostics on `.vscode/tasks.json` and `.claude/settings.json`.**
  Open or save either file and the CLI's new `hooks` scan (CLI 1.8.0) paints
  each finding on its real line: a `runOn: "folderOpen"` task or an
  auto-firing `SessionStart`/`Setup`/`InstructionsLoaded` command hook at HIGH
  is a **warning**; agent-triggered hooks and non-command hook types
  (http/mcp_tool/prompt/agent) are **information**; a file the tolerant JSONC
  reader could not parse gets one note (a warning when the raw bytes still
  mention `folderOpen` or an auto event — broken syntax is a place to hide).
- **Two new commands:** *Open-time hooks (folderOpen tasks / Claude Code)*
  runs the workspace scan in the output channel; *Open-time hooks in
  dependency tarballs (--deps)* additionally downloads every locked
  dependency's tarball — a shipped folderOpen task is HIGH regardless of its
  command (the hijacked `html-to-gutenberg`/`fetch-page-assets` releases hid
  one named "eslint-check").
- Activation now also triggers on workspaces carrying `.vscode/tasks.json` or
  `.claude/settings.json`. On a CLI older than 1.8.0 the hooks scan degrades
  to a one-line note in the output channel; nothing else changes.

## 1.7.0

Version jumps 1.4.0 → 1.7.0 to line back up with the CLI it fronts. If you
installed from the Marketplace you were on 1.3.0, so this release also delivers
everything under 1.4.0 below — the decision-aware diagnostics are the headline.

- **New command: *Publish readiness (npm token cliff)*.** Runs the CLI's
  `publish` command: will this repo's release workflow still publish after
  npm's January-2027 change (bypass-2FA tokens lose direct publish)? Classifies
  every CI publish path as TRUSTED / STAGED / TOKEN / UNKNOWN and prints the
  YAML patch and the npmjs.com trusted-publisher checklist when something needs
  moving.
- Because the extension shells out to `npx npm-script-lens`, CLI gains since
  1.4.0 arrive with no extension change: `publish` now follows local composite
  actions and reusable workflows instead of reporting a false all-clear
  (CLI 1.7.0), and `audit --cooldown` can refuse versions published too
  recently to have been caught (CLI 1.6.0 — a CI flag; the editor audit is
  unaffected).

## 1.4.0

**The diagnostic now knows what you already decided.** Through 1.3.0 the
extension graded every scripted dependency on behavioral risk alone and ignored
the allowlist sitting in the same file. So `allow --write` — the action the
warning exists to prompt — did not clear the warning. The squiggle outlived the
decision, forever, and the Problems panel became something to scroll past.

`audit --json` has always returned its `allowScripts` recommendation alongside
the results; the extension parsed it out and threw it away. It is now read, and
crossed with the decision recorded in your package manager's native allowlist:

| your allowlist | analysis | shown as |
| --- | --- | --- |
| *(no entry)* | risky | **warning** — the one actionable state |
| `true` | agrees | nothing |
| `true` | would have held it back | information: *allowed in your allowlist, overriding the recommendation* |
| `false` | anything | nothing — the script never runs |
| anything | known-malicious | **error**, always |

That last row is deliberate: an allowlist entry is older than any advisory
published after it, so a recorded `true` can never silence OSV.

- **All four allowlist formats are read**, matching what the CLI writes:
  npm `allowScripts` (by `pkg@version` or bare name), pnpm `allowBuilds` in
  `pnpm-workspace.yaml`, yarn `dependenciesMeta.<pkg>.built`, bun
  `trustedDependencies`. bun's list is presence-only — it cannot express a
  denial — so an absent name stays *undecided* rather than being read as denied.
- **pnpm-workspace.yaml gets diagnostics of its own.** pnpm is the one manager
  whose decisions live outside `package.json`, so overrides are anchored on their
  `allowBuilds` line.
- **Writing commands refresh the editor.** `allow --write` and `sync --write`
  change the allowlist on disk, where no save event fires — diagnostics used to
  sit stale until you touched the file. They now re-audit on completion.
- **The status bar leads with what needs a ruling** — `🔴 2 install scripts to
  review`, falling back to `🟢 3 scripted deps, none to review (1 override)`.
- A package.json that does not parse (mid-edit) yields *no* decisions, never
  blanket approval.
- **A denial wins over a trust recorded elsewhere.** A repo that has used more
  than one manager keeps more than one allowlist, and they can disagree. Reading
  them last-writer-wins let a stale bun `trustedDependencies` entry silently
  re-enable a script an npm `allowScripts: false` had blocked; a `false` from any
  file now sticks.

**Transitive risk is no longer invisible.** Most install-time risk is not a line
in your `package.json` — it arrives through a package you never typed. Those
findings were counted in the status bar and then dropped from the editor,
because there was no line to anchor them to: the count said "2 to review" and
only one squiggle existed. They now anchor on the direct dependency that pulled
them in, tagged `(via a → b)` — the line you can actually act on. A package
reachable from nothing in the manifest is still skipped, and there is now a test
asserting the count and the squiggles agree.

Also fixed:

- **An un-analyzable package no longer renders as a `Hint`.** When a tarball
  can't be fetched the CLI reports whatever risk it had — often `SAFE` — and the
  risk table turned "we don't know what this does" into a dotted underline
  nobody reads. It is an open question, so it shows as information.
- **Editing one allowlist file repaints the other.** `package.json` and
  `pnpm-workspace.yaml` are one decision surface: denying a package in the pnpm
  file clears its warning in `package.json`. Refreshing only the saved document
  left the other asserting something no longer true. One audit now repaints
  every open allowlist file in the workspace.

Message rendering, same release:

- **Repeated signals collapse.** gyp emits one signal per action invocation, so
  the same command arrived several times with extra trailing args. On
  `better-sqlite3` that produced a 273-character squiggle whose last two thirds
  were one gyp action printed twice. Identical signals now appear once, and a
  signal that is only a longer spelling of one already shown is dropped.
- **gyp macro syntax is rendered, not dumped.** `<(SHARED_INTERMEDIATE_DIR)`
  reads as `$SHARED_INTERMEDIATE_DIR`; `<!(`, `>!(`, `<@(` likewise.
- **No more `(npm-script-lens)` suffix** — the extension sets
  `diagnostic.source`, which VS Code already renders, so the name appeared twice.
- **A clean install script no longer gets a squiggle.** SAFE results were `Hint`
  diagnostics, drawn as a dotted underline on a dependency with nothing wrong
  with it. They are a status-bar count now.
- Overflow past six signals reads `+3 more` instead of a bare `…`.
- Every message ends in the action it wants: *undecided — run "Generate
  allowlist"*, *allowed in your allowlist…*, *remove it — an allowlist entry
  cannot make this safe*.

## 1.3.0

Version now tracks the CLI it fronts, so `npx npm-script-lens` and the extension
no longer report different numbers.

- **Two new commands**, exposing CLI capabilities the extension had never surfaced:
  - *Sync allowlist with the lockfile* — reconciles your package manager's native
    allowlist and drops stale entries (`sync --write`).
  - *Least-privilege .npmrc sources* — the minimal `allow-git` / `allow-remote`
    your dependency tree actually needs (`sources`).
- **`binding.gyp` findings now appear inline.** The extension is a thin shell over
  the CLI, so the gyp lens added in CLI 1.3.0 — command expansion (`<!(`, `>!(`,
  `^!(`), `pymod_do_main`, build actions, `make_global_settings` compiler hijacks —
  surfaces on the dependency's line with no extension change. Native packages with
  no install script at all are the case this catches.

## 1.0.0

- Initial release: inline install-script risk diagnostics on `package.json`,
  a workspace status-bar summary, and commands to audit, generate the
  allowlist (`allow --write`), review pending approvals, and run `doctor`.
  Powered by the npm-script-lens CLI (npm / pnpm / yarn / bun).
