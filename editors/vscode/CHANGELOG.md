# Changelog

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
