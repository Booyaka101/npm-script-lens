# npm-script-lens for VS Code

See what a dependency's install script actually does — **inline, while you edit `package.json`** — before you approve it under npm v12 `allowScripts`, pnpm `allowBuilds`, yarn `dependenciesMeta`, or bun `trustedDependencies`.

This extension is a thin UI over the [`npm-script-lens`](https://github.com/Booyaka101/npm-script-lens) CLI, which does the behavioral analysis (exec / network / filesystem / obfuscation), OSV malware check, and publisher-trust signals.

## Preview

Open a `package.json` and *undecided* install scripts are flagged inline, with the evidence in the message:

```text
  "dependencies": {
    "sharp": "^0.33.5",     ⚠  🔴 HIGH — sharp@0.33.5: exec: node-gyp rebuild · exec: require('child_process')
                                 · undecided — run “npm-script-lens: Generate allowlist”
    "chalk": "^5.3.0"       ·  (no install script — quiet)
  }
```

Status bar: `🛡 🔴 1 install script to review` — click to re-audit.

Run **Generate allowlist**, and the warning goes away, because you answered it:

```text
  "dependencies": {
    "sharp": "^0.33.5",     ℹ  🔴 HIGH — sharp@0.33.5: exec: node-gyp rebuild · exec: require('child_process')
                                 · allowed in your allowlist, overriding the recommendation
  },
  "allowScripts": { "sharp@0.33.5": true }
```

Status bar: `🛡 🟢 1 scripted dep, none to review (1 override)`.

A first-run **walkthrough** (Get Started → *Get started with npm-script-lens*) walks you from audit → allowlist → CI.

## A diagnostic is risk × your decision

An install script is only a *problem* while nobody has ruled on it. The extension reads the allowlist you already keep — npm `allowScripts`, pnpm `allowBuilds`, yarn `dependenciesMeta`, bun `trustedDependencies` — and only warns about what is still open:

| your allowlist | analysis | shown as |
| --- | --- | --- |
| *(no entry)* | risky | **warning** — the one actionable state |
| `true` | agrees | nothing |
| `true` | would have held it back | information: a standing override, worth re-reading |
| `false` | anything | nothing — the script never runs |
| anything | known-malicious | **error**, always |

An allowlist entry is older than any advisory published after it, so approving a package can never silence OSV. And because bun's `trustedDependencies` is presence-only — there is no way to spell a denial — an absent name counts as *undecided*, not denied.

## What it does

- **Inline diagnostics** on `package.json` (and on `pnpm-workspace.yaml`, the one place a decision lives outside `package.json`): every undecided dependency whose install script spawns processes, reaches the network, or is flagged malicious gets a squiggle on its line, with the evidence in the message. Decided and clean packages stay quiet.
- **Status bar** summary, leading with how many packages still need a ruling.
- **Commands** (Command Palette):
  - **npm-script-lens: Audit install scripts**
  - **npm-script-lens: Generate allowlist (write)** — runs `allow --write` for your detected package manager
  - **npm-script-lens: Sync allowlist with the lockfile** — reconciles the native allowlist, dropping stale entries
  - **npm-script-lens: Review pending approvals**
  - **npm-script-lens: Least-privilege .npmrc sources** — the minimal `allow-git` / `allow-remote` your tree actually needs
  - **npm-script-lens: Doctor (npm compatibility)**

## It reads inside `binding.gyp`

Native packages often have no install script at all — npm runs an implicit
`node-gyp rebuild`, and gyp *executes* the commands inside `binding.gyp` before a
line of C is compiled. That is where the June 2026 campaign hid its payload
([ReversingLabs](https://www.reversinglabs.com/blog/npm-bindinggyp-cicd-secrets),
286 malicious versions across 56 packages).

The CLI reads inside `binding.gyp` and the `.gypi` files it includes — command
expansion (`<!(`, and the late `>!(` / `^!(` forms), `pymod_do_main`, build
actions, and compiler hijacks via `make_global_settings` — so those findings show
up on the line in your `package.json` like any other.

## Requirements

The `npm-script-lens` CLI. By default the extension runs it via `npx npm-script-lens`; set `npmScriptLens.command` to an absolute path or a globally installed binary to avoid the `npx` fetch.

## Settings

- `npmScriptLens.command` — how to invoke the CLI (default `npx npm-script-lens`).
- `npmScriptLens.trust` — enable OSV/trust enrichment in the editor (slower; network). Off by default for snappy audits.

## License

MIT
