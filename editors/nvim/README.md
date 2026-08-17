# npm-script-lens for Neovim

Inline install-script risk on `package.json`, powered by the [`npm-script-lens`](https://github.com/Booyaka101/npm-script-lens) CLI. Requires Neovim ≥ 0.10 (`vim.system`) and the CLI on your PATH (or set `command`).

## Install

With [lazy.nvim](https://github.com/folke/lazy.nvim):

```lua
{ "Booyaka101/npm-script-lens", dir = "editors/nvim", config = true }
```

Or point your plugin manager at the `editors/nvim` subdirectory of the repo. Zero-config: open a `package.json` and risky install scripts are surfaced as diagnostics.

## Commands

- `:NpmScriptLensAudit`: audit the current `package.json` and refresh diagnostics
- `:NpmScriptLensAllow`: `allow --write` (generate the allowlist), then re-audit
- `:NpmScriptLensReview`: show pending approvals
- `:NpmScriptLensDoctor`: npm-compatibility check

## Configuration

```lua
require("npm-script-lens").setup({
  command = "npx npm-script-lens", -- or an absolute path / global binary
  trust = false,                    -- OSV + publisher-trust enrichment (slower)
  auto = true,                      -- audit package.json on read/write
})
```

Diagnostics use standard `vim.diagnostic`, so they show up in your signs, virtual text, and location list like any LSP.
