# npm-script-lens for VS Code

See what a dependency's install script actually does, **inline, while you edit `package.json`**, before you approve it under npm v12 `allowScripts`, pnpm `allowBuilds`, yarn `dependenciesMeta`, or bun `trustedDependencies`.

This extension is a thin UI over the [`npm-script-lens`](https://github.com/Booyaka101/npm-script-lens) CLI, which does the behavioral analysis (exec / network / filesystem / obfuscation), OSV malware check, and publisher-trust signals.

## Preview

Open a `package.json` and every dependency that runs code at install time is
flagged on its own line, in words rather than in analyzer output:

```text
  "dependencies": {
    "vite": "^7.2.6",       ⚠  esbuild@0.27.3 (pulled in by vite) runs code when you install it:
                               runs other programs, uses the network and reads and writes files.
                               You have not approved or blocked it yet.
    "chalk": "^5.3.0"       ·  (no install script, quiet)
  }
```

Hover it for the evidence, with the decision it is asking for right there:

```text
  esbuild@0.27.3 — waiting on your decision

  vite pulls it in. Installing it runs postinstall → node install.js on this machine.

  ✓ Approve · ⊘ Block · ☰ Show every finding

  - runs other programs — child_process.execFileSync(), npm install --no-audit …, +2 more
  - uses the network — https.get
  - reads and writes files — fs2.chmodSync, +1 more
  - reads your environment variables — process.env

  Rated HIGH: it runs other programs, and anything your own shell could do, it can do.

  Who published it — 61,234,567 downloads a week · published 12 days ago ·
  built from github.com/evanw/esbuild by .github/workflows/release.yml.

  What to do — approve and it installs as normal, block and the script never runs.
```

The buttons sit under the opening line rather than at the end for a reason: a
hover caps its height, and in a real editor there are only about six lines
before the rest is scrolled out of sight. Summary, decide, then detail.

Click **Approve**, and the decision is written into your own package manager's
allowlist as a normal edit: it lands in the undo stack, it shows up in the diff,
and it is byte for byte what the CLI would have written.

```json
  "allowScripts": { "esbuild@0.27.3": true }
```

The same two buttons are on <kbd>Ctrl</kbd>+<kbd>.</kbd>, and in the **Install
scripts** panel in the activity bar, which lists every scripted dependency in
the project grouped by what is left to do:

```text
  ⚠ Needs a decision (4)
      @prisma/engines@5.22.0   runs other programs, uses the network and reads and writes files · via prisma
      sharp@0.33.5             runs other programs, assembles code while it runs, reads your environment
      core-js@3.38.1           reads and writes files and reads your environment variables
      prisma@5.22.0            reads your environment variables
  ✓ Approved (12)
  ⊘ Blocked (1)
```

Status bar: `🛡 4 install scripts to review`. Click it to open the panel.

A first-run **walkthrough** (Get Started → *Get started with npm-script-lens*) walks you from audit → allowlist → CI.

## A diagnostic is risk × your decision

An install script is only a *problem* while nobody has ruled on it. The extension reads the allowlist you already keep (npm `allowScripts`, pnpm `allowBuilds`, yarn `dependenciesMeta`, bun `trustedDependencies`) and only warns about what is still open:

| your allowlist | analysis | shown as |
| --- | --- | --- |
| *(no entry)* | risky | **warning**, the one actionable state |
| `true` | agrees | nothing |
| `true` | would have held it back | information: a standing override, worth re-reading |
| `false` | anything | nothing, the script never runs |
| anything | known-malicious | **error**, always |

An allowlist entry is older than any advisory published after it, so approving a package can never silence OSV. And because bun's `trustedDependencies` is presence-only, with no way to spell a denial, an absent name counts as *undecided*, not denied.

## What it does

- **Inline diagnostics** on `package.json` (and on `pnpm-workspace.yaml`, the one place a decision lives outside `package.json`): every undecided dependency whose install script spawns processes, reaches the network, or is flagged malicious gets a squiggle on its line. The message says what the script can do in plain words; the hover carries the lifecycle command, the raw signals behind each claim, and the publisher. Decided and clean packages stay quiet.
- **Approve or block one package, from the finding**: on the hover, on <kbd>Ctrl</kbd>+<kbd>.</kbd>, or from the panel. The edit goes into whichever allowlist your package manager actually reads (npm `allowScripts`, pnpm `allowBuilds`, yarn `dependenciesMeta`, bun `trustedDependencies`), through the normal editor edit path so it is undoable and reviewable. A test in this repo diffs it against the CLI's own writer to keep the two byte-identical.
- **The Install scripts panel** (activity bar): every scripted dependency in the project, not just the ones with a line in your `package.json`, grouped into needs-a-decision / approved / approved-against-advice / blocked, worst risk first. Inline approve and block on each row, and clicking one jumps to the dependency that pulled it in.
- **Re-audits when the lockfile changes.** `npm install` rewriting `package-lock.json` is the moment new install scripts arrive, and it happens without any document of yours being saved.
- **Inline diagnostics on the open-time surface**: `.vscode/tasks.json` and `.claude/settings.json`, the two files the 2026-08-04 keyv worm used for persistence (Wiz: *"Persistence is attempted via Claude Code hooks and VS Code `tasks.json`"*). A task with `"runOn": "folderOpen"` or an auto-firing `SessionStart`/`Setup`/`InstructionsLoaded` command hook gets a warning on its own line, classified through the same risk ladder as the audit; agent-triggered hooks and non-command hook types show as information. Needs CLI ≥ 1.8.0 (degrades to a note in the output channel on older CLIs).
- **Status bar** summary, leading with how many packages still need a ruling.
- **Commands** (Command Palette):
  - **npm-script-lens: Audit install scripts**
  - **npm-script-lens: Approve everything still undecided** / **Block everything still undecided**: the bulk answer, after showing you exactly what it covers
  - **npm-script-lens: Generate allowlist (write)**: runs `allow --write` for your detected package manager
  - **npm-script-lens: Sync allowlist with the lockfile**: reconciles the native allowlist, dropping stale entries
  - **npm-script-lens: Review pending approvals**
  - **npm-script-lens: Least-privilege .npmrc sources**: the minimal `allow-git` / `allow-remote` your tree actually needs
  - **npm-script-lens: Doctor (npm compatibility)**
  - **npm-script-lens: Publish readiness (npm token cliff)**: will this repo's release workflow survive npm's January-2027 token change, and is the fix available here (`publish`)
  - **npm-script-lens: Open-time hooks (folderOpen tasks / Claude Code)**: scan the working tree for code that runs when the folder is *opened*, not installed (`hooks`)
  - **npm-script-lens: Open-time hooks in dependency tarballs (--deps)**: also download and scan every locked dependency's tarball; a shipped folderOpen task is HIGH regardless of its command (`hooks --deps`)

## It reads inside `binding.gyp`

Native packages often have no install script at all. npm runs an implicit
`node-gyp rebuild`, and gyp *executes* the commands inside `binding.gyp` before a
line of C is compiled. That is where the June 2026 campaign hid its payload
([ReversingLabs](https://www.reversinglabs.com/blog/npm-bindinggyp-cicd-secrets),
286 malicious versions across 56 packages).

The CLI reads inside `binding.gyp` and the `.gypi` files it includes: command
expansion (`<!(`, and the late `>!(` / `^!(` forms), `pymod_do_main`, build
actions, and compiler hijacks via `make_global_settings`. Those findings show
up on the line in your `package.json` like any other.

## Requirements

The `npm-script-lens` CLI. By default the extension runs it via `npx npm-script-lens`; set `npmScriptLens.command` to an absolute path or a globally installed binary to avoid the `npx` fetch.

## Settings

- `npmScriptLens.command`: how to invoke the CLI (default `npx npm-script-lens`).
- `npmScriptLens.trust`: check OSV for known-malicious versions and fetch publisher signals, so a hover can tell you the version you are about to approve was published yesterday by a package with no provenance attestation. On by default, one registry request per flagged package, cached for 24h.
- `npmScriptLens.auditOnOpen`: audit a project as soon as one of its `package.json` files is opened. On by default.

## License

MIT
