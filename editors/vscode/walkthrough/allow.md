# Generate your allowlist

**npm-script-lens: Generate allowlist (write)** splits every package with an install script into two buckets:

- **auto-approved**: behavioral analysis found it harmless (SAFE/LOW). Written straight into your allowlist.
- **`_review`**: spawns processes, reaches the network, is known-malicious, or couldn't be fetched. Held back for a human.

It writes your package manager's **native** format, auto-detected from the lockfile:

| manager | allowlist | file |
|---|---|---|
| npm | `allowScripts` | package.json |
| pnpm | `allowBuilds` | pnpm-workspace.yaml |
| yarn Berry | `dependenciesMeta.built` | package.json |
| bun | `trustedDependencies` | package.json |

Prefer to see the actual script source first? Run **npm-script-lens: Review pending approvals**.
