# npm-script-lens for VS Code

See what a dependency's install script actually does — **inline, while you edit `package.json`** — before you approve it under npm v12 `allowScripts`, pnpm `allowBuilds`, yarn `dependenciesMeta`, or bun `trustedDependencies`.

This extension is a thin UI over the [`npm-script-lens`](https://github.com/Booyaka101/npm-script-lens) CLI, which does the behavioral analysis (exec / network / filesystem / obfuscation), OSV malware check, and publisher-trust signals.

## Preview

Open a `package.json` and risky install scripts are flagged inline, with the evidence in the message:

```text
  "dependencies": {
    "sharp": "^0.33.5",     ⚠  🔴 HIGH — sharp@0.33.5: exec: node-gyp rebuild · exec: require('child_process')
    "core-js": "^3.38.1",   ⚠  🟡 LOW — core-js@3.38.1: env: process.env · fs: fs.writeFileSync
    "chalk": "^5.3.0"       ·  (no install script — quiet)
  }
```

Status bar: `🛡 🔴 2 high-risk install scripts` — click to re-audit.

A first-run **walkthrough** (Get Started → *Get started with npm-script-lens*) walks you from audit → allowlist → CI.

## What it does

- **Inline diagnostics** on `package.json`: every dependency whose install script spawns processes, reaches the network, or is flagged malicious gets a squiggle on its line, with the evidence in the message. Clean packages stay quiet.
- **Status bar** summary of the workspace's install-script risk.
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
