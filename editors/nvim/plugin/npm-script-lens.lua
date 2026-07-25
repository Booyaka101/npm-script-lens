-- Auto-load: zero-config setup. Users who want to override settings can call
-- require('npm-script-lens').setup({ command = '...', trust = true }) themselves
-- (guarded so a manual setup wins).
if vim.g.loaded_npm_script_lens then
  return
end
vim.g.loaded_npm_script_lens = true
require("npm-script-lens").setup()
