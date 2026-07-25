-- npm-script-lens for Neovim: inline install-script risk on package.json.
-- Thin client over the CLI (audit --json); the analysis lives in the CLI.
local M = {}

M.config = {
  command = "npx npm-script-lens", -- how to invoke the CLI
  trust = false, -- OSV/trust enrichment (slower)
  auto = true, -- audit package.json on read/write
}

local ns = vim.api.nvim_create_namespace("npm-script-lens")

local SEVERITY = {
  MALICIOUS = vim.diagnostic.severity.ERROR,
  HIGH = vim.diagnostic.severity.WARN,
  MEDIUM = vim.diagnostic.severity.WARN,
  LOW = vim.diagnostic.severity.INFO,
  SAFE = vim.diagnostic.severity.HINT,
  ERROR = vim.diagnostic.severity.INFO,
}

local function risk_of(r)
  if r.malicious then return "MALICIOUS" end
  return r.risk or "SAFE"
end

-- 0-based line index where `"name":` is declared, or nil. Exact match (no
-- substring), pattern-safe for scoped names.
function M.find_dep_line(lines, name)
  local esc = name:gsub("[%-%.%+%[%]%(%)%$%^%%%?%*]", "%%%1")
  local pat = '^%s*"' .. esc .. '"%s*:'
  for i, line in ipairs(lines) do
    if line:find(pat) then return i - 1 end
  end
  return nil
end

-- Turn CLI audit results into vim.diagnostic items for the given buffer lines.
-- Pure (no editor state) so it is unit-testable.
function M.build_diagnostics(lines, results)
  local out = {}
  for _, r in ipairs(results) do
    local scripted = (r.rows and #r.rows > 0) or r.malicious or r.error
    if scripted then
      local ln = M.find_dep_line(lines, r.name)
      if ln then
        local sigs = {}
        for _, row in ipairs(r.rows or {}) do
          for _, s in ipairs(row.signals or {}) do sigs[#sigs + 1] = s end
        end
        local risk = risk_of(r)
        local detail
        if r.malicious then
          detail = "malicious: " .. table.concat(r.advisories or {}, ", ")
        elseif #sigs > 0 then
          detail = table.concat(sigs, " · ")
        else
          detail = "has an install script"
        end
        out[#out + 1] = {
          lnum = ln,
          col = 0,
          severity = SEVERITY[risk] or vim.diagnostic.severity.INFO,
          source = "npm-script-lens",
          message = risk .. " — " .. r.name .. "@" .. r.version .. ": " .. detail,
        }
      end
    end
  end
  return out
end

-- Extract the results array from `audit --json` stdout (tolerant of leading logs).
function M.parse_results(stdout)
  local i = stdout:find("{")
  if not i then return nil end
  local ok, j = pcall(vim.json.decode, stdout:sub(i))
  if ok and type(j) == "table" and type(j.results) == "table" then return j.results end
  return nil
end

local function cli_args(extra)
  local cmd = vim.split(M.config.command, " ", { trimempty = true })
  vim.list_extend(cmd, extra)
  return cmd
end

-- Audit the buffer's package.json and publish diagnostics.
function M.audit(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local file = vim.api.nvim_buf_get_name(bufnr)
  if vim.fn.fnamemodify(file, ":t") ~= "package.json" then return end
  local cwd = vim.fn.fnamemodify(file, ":h")
  local args = { "audit", "--json" }
  if not M.config.trust then args[#args + 1] = "--no-trust" end
  vim.system(cli_args(args), { cwd = cwd, text = true }, function(res)
    local results = M.parse_results(res.stdout or "")
    if not results then return end
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local diags = M.build_diagnostics(lines, results)
    vim.schedule(function() vim.diagnostic.set(ns, bufnr, diags) end)
  end)
end

-- Run an arbitrary subcommand and echo its output (for allow/review/doctor).
function M.run(extra)
  local cwd = vim.fn.fnamemodify(vim.api.nvim_buf_get_name(0), ":h")
  vim.system(cli_args(extra), { cwd = cwd, text = true }, function(res)
    vim.schedule(function()
      vim.notify((res.stdout or "") .. (res.stderr or ""), vim.log.levels.INFO, { title = "npm-script-lens" })
      if extra[1] == "allow" or extra[1] == "sync" then M.audit(0) end
    end)
  end)
end

function M.setup(opts)
  M.config = vim.tbl_extend("force", M.config, opts or {})
  vim.api.nvim_create_user_command("NpmScriptLensAudit", function() M.audit(0) end, {})
  vim.api.nvim_create_user_command("NpmScriptLensAllow", function() M.run({ "allow", "--write" }) end, {})
  vim.api.nvim_create_user_command("NpmScriptLensReview", function() M.run({ "review" }) end, {})
  vim.api.nvim_create_user_command("NpmScriptLensDoctor", function() M.run({ "doctor" }) end, {})
  if M.config.auto then
    vim.api.nvim_create_autocmd({ "BufReadPost", "BufWritePost" }, {
      pattern = "package.json",
      callback = function(ev) M.audit(ev.buf) end,
    })
  end
  return M
end

return M
