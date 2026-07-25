-- Headless test for the Neovim plugin's pure logic + command registration.
-- Run: nvim --headless --clean -c "luafile editors/nvim/test/run.lua"
local ok, err = pcall(function()
  vim.opt.runtimepath:append(vim.fn.getcwd() .. "/editors/nvim")
  local m = require("npm-script-lens")

  local lines = {
    "{", '  "dependencies": {', '    "sharp": "^0.33.5",', '    "chalk": "^5.3.0"', "  }", "}",
  }
  assert(m.find_dep_line(lines, "sharp") == 2, "find sharp line")
  assert(m.find_dep_line(lines, "chalk") == 3, "find chalk line")
  assert(m.find_dep_line(lines, "not-here") == nil, "absent → nil")

  local results = {
    { name = "sharp", version = "0.33.5", risk = "HIGH", rows = { { signals = { "exec: node-gyp rebuild" } } } },
    { name = "chalk", version = "5.3.0", risk = "SAFE", rows = {} },
    { name = "evil", version = "1.0.0", malicious = true, advisories = { "MAL-1" }, rows = {} },
  }
  local diags = m.build_diagnostics(lines, results)
  assert(#diags == 1, "only sharp anchored (chalk clean; evil not in manifest) — got " .. #diags)
  assert(diags[1].lnum == 2, "sharp diagnostic on line 2")
  assert(diags[1].severity == vim.diagnostic.severity.WARN, "HIGH → WARN")
  assert(diags[1].message:find("node%-gyp"), "message carries the signals")

  local r = m.parse_results('add a\n{"results":[{"name":"a","version":"1","risk":"LOW","rows":[]}],"allowScripts":{}}')
  assert(r and #r == 1, "parse_results tolerates leading noise")
  assert(m.parse_results("npm ERR broke") == nil, "parse_results rejects garbage")

  m.setup({ auto = false })
  assert(vim.fn.exists(":NpmScriptLensAudit") == 2, "audit command registered")
  assert(vim.fn.exists(":NpmScriptLensAllow") == 2, "allow command registered")
  assert(vim.fn.exists(":NpmScriptLensDoctor") == 2, "doctor command registered")
end)

if ok then
  print("NVIM-PLUGIN-OK")
  vim.cmd("qa")
else
  print("NVIM-PLUGIN-FAIL: " .. tostring(err))
  vim.cmd("cquit 1")
end
