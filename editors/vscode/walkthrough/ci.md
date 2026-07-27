# Enforce it in CI

Keep the allowlist honest without thinking about it:

- **`npx npm-script-lens init`** scaffolds a `script-lens.policy.json` (your team's auto-approve rules — risk ceiling, capability bans, waivers) and a GitHub Action that gates every PR.
- **`init --auto-fix`** also adds a bot workflow that reconciles the allowlist on Renovate/Dependabot branches and commits it back.
- **`npm-script-lens sync --check`** fails CI when the allowlist drifts from the lockfile.
- **`npm-script-lens manifest --write`** commits a behavior receipt, and `--check` fails CI when an already-approved package changes what its install script *does* under the same version — the drift an allowlist alone cannot see.
- **`npm-script-lens doctor`** tells you if the tool has fallen out of step with your package manager.

See the [full docs](https://github.com/Booyaka101/npm-script-lens#readme) for the GitHub Action, MCP server, and governance policy.
