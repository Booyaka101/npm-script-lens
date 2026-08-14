'use strict';
// Will this repo's release workflow still publish after npm's January-2027
// change? The GitHub changelog of 2026-07-31 ("restricting npm bypass-2FA
// granular access tokens") pins it: bypass-2FA tokens lose DIRECT PUBLISH,
// keeping only private-package reads and staging a publish that a maintainer
// approves with 2FA. npm's advice is trusted publishing (OIDC) or staged
// publishing: but neither blog tells you whether the recommended fix is
// actually AVAILABLE in your repo: trusted publishing has npm/Node version
// floors and supports only hosted runners, and it needs npmjs.com-side config
// nobody pre-fills for you. This module answers all three, purely from the
// repo on disk, no network, no YAML dependency (the same tolerant-reader
// philosophy as src/gyp.js: enough structure to answer our questions, never a
// throw; anything unparseable can only make a path UNKNOWN, never a crash).
//
// Every date, floor, provider list and command name comes from PUBLISH in
// npm-contract.js, verified verbatim against docs.npmjs.com/trusted-publishers,
// docs.npmjs.com/staged-publishing and the 2026-07-31 changelog.
//
// Where things live:
//   this file          finds publish paths and classifies their auth
//                      (scanners per provider, then analyzePublish/checkPublish)
//   publish/yaml.js    the tolerant CI-config reader every scanner runs on
//   publish/gates.js   triggers and the six release-gate classes
//   publish/report.js  the rendered report, --json, SARIF and failure messages
//   publish/refs.js    how cited issue links and registry hosts are printed
// Adding a CI provider means a scanner here plus a gate reader in gates.js.
const fs = require('node:fs');
const path = require('node:path');
const { PUBLISH } = require('./npm-contract');
const { workflowFiles } = require('./v12gaps');
const { versionGte } = require('./sources');
const { unquote, parseYamlish, child, commandLines } = require('./publish/yaml');
const { shortIssue, registryHost } = require('./publish/refs');
const {
  GATE, classifyGate, readTriggers, gitlabGate, circleciApproval,
  REQUIRE_GATE_VALUES, GATE_RANK, REQUIRE_GATE_BAR,
} = require('./publish/gates');
const {
  renderPublish, publishJson, publishFindings,
  dangerousFailureMessage, ungatedFailureMessage, tokenFailureMessage, brokenFailureMessage,
} = require('./publish/report');

// --- publish-step detection ------------------------------------------------
// Order matters: `yarn npm publish` contains `npm publish`, and
// `npm stage publish` must not read as a plain `npm publish`.
const RUN_PUBLISHERS = [
  { tool: 'npm stage publish', re: /\bnpm\s+stage\s+publish\b/, staged: true },
  { tool: 'yarn npm publish', re: /\byarn\s+npm\s+publish\b/ },
  { tool: 'pnpm publish', re: /\bpnpm\s+publish\b/ },
  { tool: 'npm publish', re: /\bnpm\s+publish\b/ },
  { tool: 'semantic-release', re: /\bsemantic-release\b/ },
];

// `np` is too short for a bare word-boundary regex (it appears inside npm,
// pnpm, snap…): it counts only as the command word of a shell segment,
// optionally behind npx/yarn dlx/pnpm dlx.
function isNpRelease(text) {
  return text.split(/&&|\|\||;|\|/).some((seg) => {
    const words = seg.trim().split(/\s+/);
    let i = 0;
    while (words[i] === 'npx' || (words[i] === 'yarn' && words[i + 1] === 'dlx') || (words[i] === 'pnpm' && words[i + 1] === 'dlx')) {
      i += words[i] === 'npx' ? 1 : 2;
    }
    return words[i] === 'np' || (words[i] || '').match(/^np@[\w.^~-]+$/);
  });
}

function detectRunPublisher(text) {
  for (const p of RUN_PUBLISHERS) if (p.re.test(text)) return { tool: p.tool, staged: Boolean(p.staged) };
  if (isNpRelease(text)) return { tool: 'np', staged: false };
  return null;
}

// Marketplace actions that publish to npm for you.
const USES_PUBLISHERS = ['JS-DevTools/npm-publish', 'changesets/action'];
function detectUsesPublisher(uses) {
  if (typeof uses !== 'string') return null;
  const bare = unquote(uses).split('@')[0];
  return USES_PUBLISHERS.find((u) => bare.toLowerCase() === u.toLowerCase()) || null;
}

const TOKEN_ENV_KEYS = ['NODE_AUTH_TOKEN', 'NPM_TOKEN'];

// {key, value, line} for the first long-lived-token env entry under a node.
function tokenEnvEntry(envNode) {
  for (const c of (envNode && envNode.children) || []) {
    if (TOKEN_ENV_KEYS.includes(c.key)) return { key: c.key, value: c.value, line: c.line };
  }
  return null;
}

// `permissions: write-all` or an explicit `id-token: write`, workflow or job.
function idTokenGrant(permNode) {
  if (!permNode) return null;
  if (permNode.value !== null && unquote(permNode.value) === 'write-all') return { line: permNode.line, via: 'write-all' };
  const it = child(permNode, 'id-token');
  if (it && it.value !== null && unquote(it.value) === 'write') return { line: it.line, via: 'id-token: write' };
  return null;
}

// --- runner eligibility ----------------------------------------------------
// The trusted-publishing docs support only GitHub-hosted runners (plus
// GitLab.com shared runners and CircleCI cloud): "Self-hosted runners are not
// currently supported but are planned for future releases."
const HOSTED_RE = /^(ubuntu|windows|macos)-/i;

function classifyRunsOn(runsOnNode) {
  if (!runsOnNode) return { label: null, kind: 'unknown' };
  const labels = [];
  if (runsOnNode.value !== null) {
    const v = unquote(runsOnNode.value);
    if (v.startsWith('[')) labels.push(...v.replace(/^\[|\]$/g, '').split(',').map((s) => unquote(s)));
    else labels.push(v);
  }
  for (const c of runsOnNode.children) {
    if (c.item && c.value) labels.push(unquote(c.value));
    else if (c.key === 'group' && c.value) return { label: `group: ${unquote(c.value)}`, kind: 'self-hosted' };
    else if (c.key === 'labels') labels.push(...commandLines(c).map((l) => unquote(l.text)));
  }
  const label = labels.join(', ') || null;
  if (labels.some((l) => /self-hosted/i.test(l))) return { label, kind: 'self-hosted' };
  if (labels.some((l) => l.includes('${{'))) return { label, kind: 'dynamic' };
  if (labels.length > 0 && labels.every((l) => HOSTED_RE.test(l))) return { label, kind: 'github-hosted' };
  if (labels.length > 0) return { label, kind: 'self-hosted' }; // a non-GitHub-hosted label
  return { label, kind: 'unknown' };
}

// --- version floors --------------------------------------------------------
// Is a setup-node `node-version` pin below `floor` ("22.14.0")? Only a
// leading numeric pin can answer: '20' / '20.x' / '20.11.1' do, 'lts/*' and
// '${{ matrix.node }}' return null (unknown). A bare major ('22') or '22.x'
// floats to the newest 22.x, which satisfies a 22.x floor.
function nodePinBelowFloor(spec, floor) {
  if (typeof spec !== 'string') return null;
  const m = unquote(spec).replace(/^v/, '').match(/^(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/);
  if (!m) return null;
  const [fMaj, fMin, fPatch] = floor.split('.').map(Number);
  const major = Number(m[1]);
  if (major !== fMaj) return major < fMaj;
  if (m[2] === undefined || m[2] === 'x' || m[2] === '*') return false;
  if (Number(m[2]) !== fMin) return Number(m[2]) < fMin;
  if (m[3] === undefined || m[3] === 'x' || m[3] === '*') return false;
  return Number(m[3]) < fPatch;
}

// The lower bound a package.json engines.node range admits ("">=18"" → 18.0.0)
// null when there is none or it cannot be read.
function enginesMinimum(enginesNode) {
  if (typeof enginesNode !== 'string') return null;
  const m = enginesNode.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return `${m[1]}.${m[2] || 0}.${m[3] || 0}`;
}

// --- setup-node capture ----------------------------------------------------
// major resolves only from a leading numeric ref (v6 / 6 / v6.1.0); a SHA, a
// branch or `${{ … }}` stays null rather than becoming a guessed version.
function readSetupNode(uses, withNode, file) {
  const bare = unquote(uses.value || '');
  const at = bare.indexOf('@');
  const ref = at >= 0 ? bare.slice(at + 1) : null;
  const m = ref ? ref.match(/^v?(\d+)(?:[.\s]|$)/) : null;
  const ru = child(withNode, 'registry-url');
  return {
    ref,
    major: m ? Number(m[1]) : null,
    registryUrl: ru && ru.value !== null ? unquote(ru.value) : null,
    registryLine: ru ? ru.line : null,
    uses: bare, file, line: uses.line,
  };
}

// `sed -i '/_authToken/d'`, `grep -v`, `rm`: the workaround for setup-node's
// dummy line, so it is neither a token write nor an OIDC breakage.
function isAuthTokenStrip(text) {
  if (!/_authToken/.test(text)) return false;
  return /\bsed\b.*\/\s*d\b/.test(text)
    || /\bgrep\b\s+(-\w*v\w*\b|--invert-match\b)/.test(text)
    || (/\brm\b/.test(text) && !/>>?/.test(text));
}

// A real write: a redirect, npm config set, echo/printf/tee, or an
// `_authToken=` assignment.
function isAuthTokenWrite(text) {
  if (!/_authToken/.test(text) || isAuthTokenStrip(text)) return false;
  return /_authToken\s*=/.test(text)
    || /(>>?|\bnpm\s+config\s+set\b|\becho\b|\bprintf\b|\btee\b)/.test(text);
}

// --- classification --------------------------------------------------------
// Exactly one of TRUSTED / STAGED / TOKEN / UNKNOWN per publish path:
//   STAGED: the command is `npm stage publish`
//   TRUSTED: an id-token grant (GH permissions / GitLab id_tokens with the
//              npm audience / CircleCI NPM_ID_TOKEN) and NO auth token
//   TOKEN: NODE_AUTH_TOKEN / NPM_TOKEN in the effective env (or an
//              .npmrc write containing _authToken), and NO id-token grant
//   UNKNOWN: a publish exists but neither (or both), never a failure
function classifyAuth({ staged = false, reusable = false, token = null, idToken = null } = {}) {
  if (staged) return 'STAGED';
  if (reusable) return 'UNKNOWN';
  if (token && !idToken) return 'TOKEN';
  if (idToken && !token) return 'TRUSTED';
  return 'UNKNOWN';
}

// A TRUSTED GitHub path on setup-node v6 or older with an npmjs
// `registry-url:` is BROKEN: the step writes a dummy _authToken and npm never
// starts the OIDC exchange. An unresolvable ref gets a note, not a downgrade.
function oidcBreakage(p) {
  const o = PUBLISH.oidc;
  const none = { broken: false, note: null };
  if (!p || p.provider !== 'github' || p.classification !== 'TRUSTED') return none;
  const sn = p.setupNode;
  if (!sn || !sn.registryUrl) return none;
  if (!o.hosts.includes(registryHost(sn.registryUrl))) return none;
  // the job already strips the dummy line, the documented workaround
  if (p.authTokenStrip) return none;
  const fixedMajor = Number(o.setupNodeFixedIn.split('.')[0]);
  if (sn.major === null) {
    return {
      broken: false,
      note: `actions/setup-node is pinned to ${sn.ref}, which cannot be resolved to a version`
        + `, and if it predates v${o.setupNodeFixedIn} it writes a dummy _authToken that breaks`
        + ` this OIDC publish (${shortIssue(o.issues[0])}).`,
    };
  }
  if (sn.major < fixedMajor) return { broken: true, note: null };
  return none;
}

// --- local `uses:` resolution ----------------------------------------------
// A step's `uses: ./.github/actions/release` (or a pinned `owner/repo/path@ref`
// where owner/repo is THIS repo) is code in this working tree, resolvable
// without any network. Anything third-party returns null and stays silent: we
// cannot see inside actions/checkout@v4, and flooding every repo with UNKNOWN
// for it would drown the real signal. `uses: ./` (the repo-root action.yml) is
// the repo's own shipped Action product, not a release helper, so also null.

function resolveLocalUses(projectDir, usesValue, repo) {
  if (typeof usesValue !== 'string') return null;
  const bare = unquote(usesValue);
  let relPath = null;
  if (bare.startsWith('./')) {
    relPath = bare.slice(2).replace(/^\/+/, '');
  } else if (repo) {
    const m = bare.match(/^([^/@]+)\/([^/@]+)\/([^@]+)@(.+)$/);
    if (m && m[1].toLowerCase() === String(repo.owner).toLowerCase() && m[2].toLowerCase() === String(repo.repo).toLowerCase()) relPath = m[3];
  }
  if (!relPath) return null;
  const abs = path.join(projectDir, relPath);
  if (/\.ya?ml$/i.test(abs)) return abs;
  for (const name of ['action.yml', 'action.yaml']) {
    const candidate = path.join(abs, name);
    if (fs.existsSync(candidate)) return candidate;
  }
  // a directory with neither file still RESOLVES: the scan reports it as one
  // unreadable UNKNOWN instead of silently losing the reference
  return path.join(abs, 'action.yml');
}

// A pinned self-reference resolves from the working tree, which is HEAD, the
// ref the workflow actually runs may be older.
const pinnedRefNote = (usesValue) => {
  const bare = unquote(String(usesValue));
  const m = bare.match(/@(.+)$/);
  return m && !bare.startsWith('./') ? `. Resolved from the working tree; the pinned ref @${m[1]} may differ from HEAD` : '';
};

// {key → {value, line}} for a step's `with:` block.
function readWithMap(withNode) {
  const map = {};
  for (const c of (withNode && withNode.children) || []) {
    if (c.key) map[c.key] = { value: c.value, line: c.line };
  }
  return map;
}

// The caller-step `with:` entry that carries an npm token: a TOKEN_ENV_KEY key,
// or a value naming secrets.NPM_TOKEN / secrets.NODE_AUTH_TOKEN.
function withTokenEntry(withMap) {
  for (const [key, v] of Object.entries(withMap || {})) {
    if (TOKEN_ENV_KEYS.includes(key) || /\bsecrets\s*\.\s*(NPM_TOKEN|NODE_AUTH_TOKEN)\b/.test(String(v.value || ''))) {
      return { key, value: v.value, line: v.line };
    }
  }
  return null;
}

// A composite `env: NODE_AUTH_TOKEN: ${{ inputs.npm-token }}` resolves through
// the CALLER step's `with:` map: a fed value referencing `secrets.` (or a
// literal) is a TOKEN; an input the caller never resolves is UNKNOWN.
function resolveCompositeEnvToken(envToken, withMap) {
  if (!envToken) return { state: 'none' };
  const m = String(envToken.value || '').match(/\binputs\s*\.\s*([\w-]+)/);
  if (!m) return { state: 'token', token: envToken, where: 'in the composite step env' };
  const fed = withMap && withMap[m[1]];
  if (fed && !/\binputs\s*\./.test(String(fed.value || ''))) {
    return {
      state: 'token',
      token: { key: envToken.key, value: fed.value, line: envToken.line },
      where: `in the composite step env, fed by the caller's \`with: ${m[1]}\``,
    };
  }
  return { state: 'unresolved', key: envToken.key, input: m[1] };
}

// --- GitHub Actions --------------------------------------------------------
// ctx: { projectDir, repo, reached, pushScanned }, shared per analysis.
// inherited: set when this file is a locally-called reusable workflow
// { grant, via, workflowFile, depth, seen }. The caller job's grant stands in
// for a missing workflow-level one, and workflowFile stays the CALLING
// workflow's basename (that is what npmjs.com's trusted-publisher form wants).

function scanGithubWorkflow(file, rel, paths, ctx, inherited) {
  let root;
  try { root = parseYamlish(fs.readFileSync(file, 'utf8')); } catch { return; }
  const workflowGrant = idTokenGrant(child(root, 'permissions')) || (inherited ? inherited.grant : null);
  const workflowEnvToken = tokenEnvEntry(child(root, 'env'));
  const workflowFile = inherited ? inherited.workflowFile : path.basename(rel);
  const via = inherited ? inherited.via : undefined;
  // triggers belong to the workflow FILE; a locally-called reusable workflow
  // runs on the CALLING workflow's `on:`, its own is just `workflow_call`
  const triggers = inherited ? inherited.triggers : readTriggers(root, rel);
  const jobs = child(root, 'jobs');
  if (!jobs) return;
  for (const job of jobs.children) {
    if (!job.key) continue;
    const steps = child(job, 'steps');
    const jobUses = child(job, 'uses');
    // a job-level permissions block REPLACES the workflow-level one (GitHub
    // semantics), only inherit the workflow grant when the job declares none
    const jobPerm = child(job, 'permissions');
    const jobGrant = jobPerm ? idTokenGrant(jobPerm) : workflowGrant;
    const jobEnvToken = tokenEnvEntry(child(job, 'env')) || workflowEnvToken;
    const runner = classifyRunsOn(child(job, 'runs-on'));
    const envNode = child(job, 'environment');
    const environment = envNode
      ? (envNode.value !== null ? unquote(envNode.value) : (child(envNode, 'name') && unquote(child(envNode, 'name').value || '')) || null)
      : null;

    // reusable workflow: `uses:` with no run steps. A LOCAL one is code in
    // this working tree, scan it with this job's grant instead of giving up.
    if (jobUses && !steps) {
      const resolved = resolveLocalUses(ctx.projectDir, jobUses.value, ctx.repo);
      const relTo = (p) => path.relative(ctx.projectDir, p).replace(/\\/g, '/');
      if (resolved) ctx.reached.add(path.resolve(resolved));
      const depth = (inherited ? inherited.depth : 0) + 1;
      const seen = inherited ? inherited.seen : new Set([path.resolve(file)]);
      let reason = 'the job calls a reusable workflow, so its publish step (if any) lives in the called file; run `npm-script-lens publish` in that repo';
      if (resolved && fs.existsSync(resolved)) {
        if (depth <= 3 && !seen.has(path.resolve(resolved))) {
          seen.add(path.resolve(resolved));
          const rel2 = relTo(resolved);
          ctx.pushScanned(rel2);
          scanGithubWorkflow(resolved, rel2, paths, ctx, {
            grant: jobGrant, depth, seen, workflowFile, triggers,
            via: [...(via || []), { file: rel, line: jobUses.line, job: job.key, step: null }],
          });
          continue;
        }
        reason = `local reusable workflows nesting deeper than 3 levels (or calling themselves) are not followed. Inspect ${relTo(resolved)} directly`;
      } else if (resolved) {
        reason = `the job calls a local reusable workflow, but ${relTo(resolved)} does not exist in the working tree${pinnedRefNote(jobUses.value)}`;
      }
      paths.push({
        provider: 'github', file: rel, line: jobUses.line, job: job.key,
        tool: `reusable workflow (${unquote(jobUses.value || '?')})`,
        classification: 'UNKNOWN', reusable: true, reason,
        runner, environment, workflowFile, via,
        trigger: triggers, jobLine: job.line, jobFile: rel, ifGuard: child(job, 'if') ? 'job' : null,
      });
      continue;
    }
    if (!steps) continue;

    // setup-node pin and any .npmrc _authToken write/strip anywhere in the job
    let nodeVersion = null, nodeVersionLine = null, authTokenWrite = null, setupNode = null, authTokenStrip = null;
    for (const step of steps.children) {
      const uses = child(step, 'uses');
      if (uses && /(^|\/)setup-node(@|$)/.test(unquote(uses.value || ''))) {
        const withNode = child(step, 'with');
        const nv = child(withNode, 'node-version');
        if (nv && nv.value !== null) { nodeVersion = unquote(nv.value); nodeVersionLine = nv.line; }
        setupNode = readSetupNode(uses, withNode, rel);
      }
      for (const l of commandLines(child(step, 'run'))) {
        if (!authTokenWrite && isAuthTokenWrite(l.text)) authTokenWrite = { line: l.line, text: l.text };
        if (!authTokenStrip && isAuthTokenStrip(l.text)) authTokenStrip = { line: l.line, text: l.text };
      }
    }

    for (const step of steps.children) {
      const stepEnvToken = tokenEnvEntry(child(step, 'env'));
      const uses = child(step, 'uses');
      const usesPub = uses && detectUsesPublisher(uses.value);
      const found = [];
      for (const l of commandLines(child(step, 'run'))) {
        const hit = detectRunPublisher(l.text);
        if (hit) found.push({ ...hit, line: l.line });
      }
      if (usesPub) {
        // JS-DevTools/npm-publish takes the npm token as a `token:` input
        const withToken = usesPub === 'JS-DevTools/npm-publish' && child(child(step, 'with'), 'token');
        found.push({
          tool: usesPub, staged: false, line: uses.line,
          withToken: withToken ? { key: 'token', value: withToken.value, line: withToken.line } : null,
        });
      }
      for (const hit of found) {
        const token = stepEnvToken || hit.withToken || jobEnvToken || authTokenWrite;
        const classification = classifyAuth({ staged: hit.staged, token, idToken: jobGrant });
        paths.push({
          provider: 'github', file: rel, line: hit.line, job: job.key, tool: hit.tool,
          classification,
          reason: describeAuth({ staged: hit.staged, token, idToken: jobGrant, stepEnvToken, authTokenWrite }),
          runner, environment, workflowFile,
          nodeVersion, nodeVersionLine, setupNode, authTokenStrip,
          token: token ? { key: token.key || '_authToken', value: token.value || null, line: token.line } : null,
          idToken: jobGrant || null,
          via,
          trigger: triggers, jobLine: job.line, jobFile: rel,
          ifGuard: child(job, 'if') ? 'job' : child(step, 'if') ? 'step' : null,
        });
      }
      // a local composite action referenced by this step: scan it in place of
      // the silence a non-marketplace `uses:` used to produce
      if (uses && !usesPub && !/(^|\/)setup-node(@|$)/.test(unquote(uses.value || ''))) {
        const resolved = resolveLocalUses(ctx.projectDir, uses.value, ctx.repo);
        if (resolved) {
          const nameNode = child(step, 'name');
          const withMap = readWithMap(child(step, 'with'));
          scanComposite(resolved, path.relative(ctx.projectDir, resolved).replace(/\\/g, '/'), {
            projectDir: ctx.projectDir, repo: ctx.repo, reached: ctx.reached, pushScanned: ctx.pushScanned,
            usesRaw: unquote(uses.value || ''), withMap,
            jobGrant, callerWithToken: withTokenEntry(withMap), callerStepEnvToken: stepEnvToken, callerEnvToken: jobEnvToken,
            runner, environment, workflowFile,
            triggers, jobLine: job.line, jobFile: rel,
            ifGuard: child(job, 'if') ? 'job' : child(step, 'if') ? 'step' : null,
            nodeVersion, nodeVersionLine, nodeVersionFile: nodeVersion === null ? null : rel, setupNode, authTokenStrip,
            pinnedNote: pinnedRefNote(uses.value),
            via: [...(via || []), { file: rel, line: uses.line, job: job.key, step: nameNode ? unquote(nameNode.value || '') : null }],
          }, paths, new Set(), 1);
        }
      }
    }
  }
}

// Scan a composite action referenced (possibly transitively) by a workflow
// step. NEVER throws: unreadable, unparseable, non-composite and too-deep
// targets each yield one UNKNOWN path (same discipline as src/gyp.js).
// Composite actions cannot declare `permissions`, so the id-token grant is
// always the CALLING job's, ctx.jobGrant, passed through unchanged.
function scanComposite(file, rel, ctx, paths, seen, depth) {
  const abs = path.resolve(file);
  if (seen.has(abs)) return; // cycle: already on this resolution chain
  seen.add(abs);
  ctx.reached.add(abs);
  const from = ctx.via[ctx.via.length - 1]; // the step that referenced this file
  const base = {
    provider: 'github', job: from.job, runner: ctx.runner, environment: ctx.environment,
    workflowFile: ctx.workflowFile,
    trigger: ctx.triggers || null, jobLine: ctx.jobLine || null, jobFile: ctx.jobFile || null, ifGuard: ctx.ifGuard || null,
  };
  if (depth > 3) {
    paths.push({
      ...base, file: from.file, line: from.line, tool: `local action (${ctx.usesRaw})`,
      classification: 'UNKNOWN',
      reason: `local actions nesting deeper than 3 levels are not followed. Inspect ${rel} directly`,
      via: ctx.via.slice(0, -1),
    });
    return;
  }
  let root;
  try { root = parseYamlish(fs.readFileSync(file, 'utf8')); } catch {
    paths.push({
      ...base, file: from.file, line: from.line, tool: `local action (${ctx.usesRaw})`,
      classification: 'UNKNOWN',
      reason: `the step uses ${ctx.usesRaw}, but ${rel} cannot be read from the working tree, so its publish steps (if any) are invisible${ctx.pinnedNote}`,
      via: ctx.via.slice(0, -1),
    });
    return;
  }
  ctx.pushScanned(rel);
  const runs = child(root, 'runs');
  const using = runs && child(runs, 'using');
  if (!using || unquote(using.value || '') !== 'composite') {
    paths.push({
      ...base, file: rel, line: using ? using.line : 1, tool: `local action (${ctx.usesRaw})`,
      classification: 'UNKNOWN',
      reason: `the referenced local action is not a composite action (runs.using: ${using ? unquote(using.value || '?') : 'missing'}). Its bundled code may publish, but a static scan cannot see it${ctx.pinnedNote}`,
      via: ctx.via,
    });
    return;
  }
  const steps = child(runs, 'steps');
  if (!steps) return;

  // the caller job's setup-node pin wins; else the first pin in this composite
  // chain, attributed to the composite file that holds it
  let nodeVersion = ctx.nodeVersion, nodeVersionLine = ctx.nodeVersionLine, nodeVersionFile = ctx.nodeVersionFile;
  let authTokenWrite = null, setupNode = ctx.setupNode || null, authTokenStrip = ctx.authTokenStrip || null;
  for (const step of steps.children) {
    const uses = child(step, 'uses');
    if (uses && /(^|\/)setup-node(@|$)/.test(unquote(uses.value || ''))) {
      const withNode = child(step, 'with');
      if (nodeVersion === null) {
        const nv = child(withNode, 'node-version');
        if (nv && nv.value !== null) { nodeVersion = unquote(nv.value); nodeVersionLine = nv.line; nodeVersionFile = rel; }
      }
      if (!setupNode) setupNode = readSetupNode(uses, withNode, rel);
    }
    for (const l of commandLines(child(step, 'run'))) {
      if (!authTokenWrite && isAuthTokenWrite(l.text)) authTokenWrite = { line: l.line, text: l.text };
      if (!authTokenStrip && isAuthTokenStrip(l.text)) authTokenStrip = { line: l.line, text: l.text };
    }
  }

  for (const step of steps.children) {
    const stepEnvToken = tokenEnvEntry(child(step, 'env'));
    const uses = child(step, 'uses');
    const usesPub = uses && detectUsesPublisher(uses.value);
    const found = [];
    for (const l of commandLines(child(step, 'run'))) {
      const hit = detectRunPublisher(l.text);
      if (hit) found.push({ ...hit, line: l.line });
    }
    if (usesPub) {
      const withToken = usesPub === 'JS-DevTools/npm-publish' && child(child(step, 'with'), 'token');
      found.push({
        tool: usesPub, staged: false, line: uses.line,
        withToken: withToken ? { key: 'token', value: withToken.value, line: withToken.line } : null,
      });
    }
    for (const hit of found) {
      // token precedence, first match wins: composite step env (inputs.*
      // resolved through the caller's `with:` map) → an _authToken write in a
      // composite run line → the caller step's token-carrying `with:` entry →
      // the caller's step/job/workflow env token
      const resolvedEnv = resolveCompositeEnvToken(stepEnvToken, ctx.withMap);
      let token = null, tokenWhere = null;
      if (resolvedEnv.state === 'token') { token = resolvedEnv.token; tokenWhere = resolvedEnv.where; }
      else if (resolvedEnv.state === 'none') {
        if (hit.withToken) { token = hit.withToken; tokenWhere = 'passed as the action\'s `token` input'; }
        else if (authTokenWrite) { token = authTokenWrite; tokenWhere = 'written into .npmrc by the composite action'; }
        else if (ctx.callerWithToken) { token = ctx.callerWithToken; tokenWhere = `passed by the calling step's \`with: ${ctx.callerWithToken.key}\``; }
        else if (ctx.callerStepEnvToken) { token = ctx.callerStepEnvToken; tokenWhere = 'in the calling step env'; }
        else if (ctx.callerEnvToken) { token = ctx.callerEnvToken; tokenWhere = 'in the calling job/workflow env'; }
      }
      let classification, reason;
      if (resolvedEnv.state === 'unresolved') {
        classification = 'UNKNOWN';
        reason = `the composite step sets ${resolvedEnv.key} from inputs.${resolvedEnv.input}, but the calling step resolves no such input, so auth cannot be determined`;
      } else {
        classification = classifyAuth({ staged: hit.staged, token, idToken: ctx.jobGrant });
        reason = describeAuth({ staged: hit.staged, token, idToken: ctx.jobGrant, stepEnvToken: null, authTokenWrite: null, tokenWhere });
      }
      paths.push({
        ...base, file: rel, line: hit.line, tool: hit.tool,
        classification, reason: `${reason}${ctx.pinnedNote}`,
        ifGuard: ctx.ifGuard || (child(step, 'if') ? 'step' : null),
        nodeVersion, nodeVersionLine, nodeVersionFile, setupNode, authTokenStrip,
        token: token ? { key: token.key || '_authToken', value: token.value || null, line: token.line } : null,
        idToken: ctx.jobGrant || null,
        via: ctx.via,
      });
    }
    // recurse into a nested local action
    if (uses && !usesPub && !/(^|\/)setup-node(@|$)/.test(unquote(uses.value || ''))) {
      const nested = resolveLocalUses(ctx.projectDir, uses.value, ctx.repo);
      if (nested) {
        const nameNode = child(step, 'name');
        const withMap = readWithMap(child(step, 'with'));
        scanComposite(nested, path.relative(ctx.projectDir, nested).replace(/\\/g, '/'), {
          ...ctx, usesRaw: unquote(uses.value || ''), withMap,
          callerWithToken: withTokenEntry(withMap), callerStepEnvToken: stepEnvToken,
          nodeVersion, nodeVersionLine, nodeVersionFile, setupNode, authTokenStrip,
          pinnedNote: pinnedRefNote(uses.value) || ctx.pinnedNote,
          via: [...ctx.via, { file: rel, line: uses.line, job: from.job, step: nameNode ? unquote(nameNode.value || '') : null }],
        }, paths, seen, depth + 1);
      }
    }
  }
}

// Safety net: a composite action under .github/actions/ that publishes but is
// referenced by no scanned workflow, e.g. called from another repo. One
// UNKNOWN per file; UNKNOWN never fails --check. The repo-ROOT action.yml is
// the repo's own shipped Action product, not a release helper, so not scanned.
function scanOrphanComposites(projectDir, reached, pushScanned, paths) {
  const files = [];
  const walk = (dir, depth) => {
    if (depth > 4) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (/^action\.ya?ml$/i.test(e.name)) files.push(p);
    }
  };
  walk(path.join(projectDir, '.github', 'actions'), 1);
  for (const file of files.sort()) {
    if (reached.has(path.resolve(file))) continue;
    let root;
    try { root = parseYamlish(fs.readFileSync(file, 'utf8')); } catch { continue; }
    const rel = path.relative(projectDir, file).replace(/\\/g, '/');
    pushScanned(rel);
    const steps = child(child(root, 'runs'), 'steps');
    let hit = null;
    for (const step of (steps && steps.children) || []) {
      for (const l of commandLines(child(step, 'run'))) {
        const found = detectRunPublisher(l.text);
        if (found) { hit = { ...found, line: l.line }; break; }
      }
      if (!hit) {
        const uses = child(step, 'uses');
        const usesPub = uses && detectUsesPublisher(uses.value);
        if (usesPub) hit = { tool: usesPub, line: uses.line };
      }
      if (hit) break;
    }
    if (!hit) continue;
    paths.push({
      provider: 'github', file: rel, line: hit.line, job: null, tool: hit.tool,
      classification: 'UNKNOWN',
      reason: 'composite action defines a publish step but no scanned workflow in this repo references it, so it may be called from another repo',
      runner: { label: null, kind: 'unknown' }, environment: null,
      workflowFile: path.basename(rel), via: [],
      trigger: null,
      gate: { class: GATE.UNKNOWN, reason: 'no workflow in this repo references this composite action, so no trigger is visible' },
    });
  }
}

function describeAuth({ staged, token, idToken, stepEnvToken, authTokenWrite, tokenWhere }) {
  if (staged) return 'stages a publish; a maintainer approves with 2FA (`npm stage approve <stage-id>`); unaffected by the January 2027 change';
  if (token && idToken) return `ambiguous: both an id-token grant (line ${idToken.line}) and ${token.key || '_authToken'} (line ${token.line}) are present. Remove the token to make this a trusted-publishing path`;
  if (token) {
    const where = tokenWhere || (stepEnvToken ? 'in the publish step env' : authTokenWrite === token ? 'written into .npmrc' : 'in the job/workflow env');
    return `long-lived token: ${token.key || '_authToken'} ${where} (line ${token.line})`;
  }
  if (idToken) return `trusted publishing (OIDC): ${idToken.via} granted (line ${idToken.line}), no token in the env`;
  return 'no id-token grant and no token visible in this file, so auth may come from a checked-in .npmrc or the environment';
}

// --- GitLab CI -------------------------------------------------------------

const GITLAB_RESERVED = new Set(['stages', 'variables', 'workflow', 'default', 'include', 'image', 'services', 'before_script', 'after_script', 'cache', 'pages']);

// A job's id_tokens block counts only with the npm audience:
//   id_tokens: { NPM_ID_TOKEN: { aud: npm:registry.npmjs.org } }
function gitlabIdTokenGrant(node) {
  const block = child(node, 'id_tokens');
  if (!block) return null;
  for (const v of block.children) {
    const aud = child(v, 'aud');
    if (!aud) continue;
    const vals = aud.value !== null ? [aud.value] : commandLines(aud).map((l) => l.text);
    if (vals.some((a) => unquote(a).includes(PUBLISH.trusted.gitlabAudience))) return { line: aud.line, via: `id_tokens ${v.key} (aud ${PUBLISH.trusted.gitlabAudience})` };
  }
  return null;
}

function scanGitlabCi(file, rel, paths) {
  let root;
  try { root = parseYamlish(fs.readFileSync(file, 'utf8')); } catch { return; }
  const globalToken = tokenEnvEntry(child(root, 'variables'));
  const defaultGrant = gitlabIdTokenGrant(child(root, 'default') || { children: [] });
  for (const job of root.children) {
    if (!job.key || GITLAB_RESERVED.has(job.key) || job.key.startsWith('.')) continue;
    const scripts = ['before_script', 'script', 'after_script'].map((k) => child(job, k)).filter(Boolean);
    if (!child(job, 'script')) continue; // not a job
    const grant = gitlabIdTokenGrant(job) || defaultGrant;
    const jobToken = tokenEnvEntry(child(job, 'variables')) || globalToken;
    let authTokenWrite = null;
    for (const s of scripts) {
      for (const l of commandLines(s)) if (!authTokenWrite && isAuthTokenWrite(l.text)) authTokenWrite = { line: l.line, text: l.text };
    }
    const tags = child(job, 'tags');
    const runner = tags
      ? { label: `tags: ${commandLines(tags).map((l) => unquote(l.text)).join(', ')}`, kind: 'tagged' }
      : { label: 'gitlab.com shared runners (no tags)', kind: 'gitlab-shared' };
    const { gate, trigger, environment } = gitlabGate(job, rel);
    for (const s of scripts) {
      for (const l of commandLines(s)) {
        const hit = detectRunPublisher(l.text);
        if (!hit) continue;
        const token = jobToken || authTokenWrite;
        paths.push({
          provider: 'gitlab', file: rel, line: l.line, job: job.key, tool: hit.tool,
          classification: classifyAuth({ staged: hit.staged, token, idToken: grant }),
          reason: describeAuth({ staged: hit.staged, token, idToken: grant, stepEnvToken: null, authTokenWrite }),
          runner, environment, workflowFile: path.basename(rel),
          token: token ? { key: token.key || '_authToken', value: token.value || null, line: token.line } : null,
          idToken: grant || null,
          trigger, gate,
        });
      }
    }
  }
}

// --- CircleCI --------------------------------------------------------------

function scanCircleCi(file, rel, paths) {
  let root, text;
  try { text = fs.readFileSync(file, 'utf8'); root = parseYamlish(text); } catch { return; }
  // Trusted publishing on CircleCI arrives as the NPM_ID_TOKEN env var (set by
  // the npmjs.com trusted-publisher config + a CircleCI context); its presence
  // anywhere in the config is the grant signal we can see statically.
  const idTokenLineIdx = text.split(/\r?\n/).findIndex((l) => l.includes(PUBLISH.trusted.circleciTokenVar));
  const grant = idTokenLineIdx >= 0 ? { line: idTokenLineIdx + 1, via: PUBLISH.trusted.circleciTokenVar } : null;
  const jobs = child(root, 'jobs');
  if (!jobs) return;
  for (const job of jobs.children) {
    if (!job.key) continue;
    const steps = child(job, 'steps');
    if (!steps) continue;
    const jobToken = tokenEnvEntry(child(job, 'environment'));
    // a resource_class with a namespace slash selects a self-hosted runner
    const rc = child(job, 'resource_class');
    const runner = rc && rc.value && unquote(rc.value).includes('/')
      ? { label: `resource_class: ${unquote(rc.value)}`, kind: 'self-hosted' }
      : { label: 'circleci cloud', kind: 'circleci-cloud' };
    let authTokenWrite = null;
    const stepCommands = [];
    for (const step of steps.children) {
      const run = step.value === null ? child(step, 'run') : null;
      const cmds = run
        ? (run.value !== null || run.blockLines ? commandLines(run) : commandLines(child(run, 'command')))
        : [];
      const stepToken = run ? tokenEnvEntry(child(run, 'environment')) : null;
      for (const l of cmds) {
        stepCommands.push({ ...l, stepToken });
        if (!authTokenWrite && isAuthTokenWrite(l.text)) authTokenWrite = { line: l.line, text: l.text };
      }
    }
    const approval = circleciApproval(root, job.key);
    const gate = approval && approval.job
      ? { class: GATE.MANUAL, reason: `the "${approval.job}" approval job gates this publish in workflow "${approval.workflow}"` }
      : { class: GATE.UNKNOWN, reason: 'no approval-type job is upstream of this publish in its workflow, and CircleCI triggers and filters are not read, so the gate cannot be determined' };
    const trigger = approval && approval.job
      ? { events: [{ event: `approval: ${approval.job}`, filters: null, line: approval.line }], file: rel }
      : null;
    for (const l of stepCommands) {
      const hit = detectRunPublisher(l.text);
      if (!hit) continue;
      const token = l.stepToken || jobToken || authTokenWrite;
      paths.push({
        provider: 'circleci', file: rel, line: l.line, job: job.key, tool: hit.tool,
        classification: classifyAuth({ staged: hit.staged, token, idToken: grant }),
        reason: describeAuth({ staged: hit.staged, token, idToken: grant, stepEnvToken: l.stepToken, authTokenWrite }),
        runner, environment: null, workflowFile: path.basename(rel),
        token: token ? { key: token.key || '_authToken', value: token.value || null, line: token.line } : null,
        idToken: grant || null,
        trigger, gate,
      });
    }
  }
}

// --- repo identity (for the pre-filled npmjs.com checklist) ----------------

function repoIdentity(projectDir) {
  const fromUrl = (url) => {
    const m = String(url).match(/(?:github\.com|gitlab\.com|bitbucket\.org)[/:]([^/\s]+)\/([^/\s]+?)(?:\.git)?(?:[/#?].*)?$/i);
    return m ? { owner: m[1], repo: m[2] } : null;
  };
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    const url = typeof pkg.repository === 'string' ? pkg.repository : pkg.repository && pkg.repository.url;
    const id = url && fromUrl(url);
    if (id) return id;
  } catch { /* no package.json, try git */ }
  try {
    const cfg = fs.readFileSync(path.join(projectDir, '.git', 'config'), 'utf8');
    const m = cfg.match(/\[remote "origin"\][^[]*?url\s*=\s*(\S+)/);
    const id = m && fromUrl(m[1]);
    if (id) return id;
  } catch { /* not a git repo */ }
  return null;
}

// --- analysis --------------------------------------------------------------

const dirOf = (target) => {
  const resolved = path.resolve(target);
  return fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
};

function analyzePublish(target) {
  const projectDir = dirOf(target);
  const repo = repoIdentity(projectDir);
  let paths = [];
  const scanned = [];
  const scannedSet = new Set();
  const pushScanned = (rel) => { if (!scannedSet.has(rel)) { scannedSet.add(rel); scanned.push(rel); } };
  const reached = new Set(); // composite/workflow files some scanned workflow resolved
  const ctx = { projectDir, repo, reached, pushScanned };
  for (const file of workflowFiles(projectDir)) {
    const rel = path.relative(projectDir, file).replace(/\\/g, '/');
    pushScanned(rel);
    scanGithubWorkflow(file, rel, paths, ctx, null);
  }
  for (const [rel, scan] of [['.gitlab-ci.yml', scanGitlabCi], ['.circleci/config.yml', scanCircleCi]]) {
    const file = path.join(projectDir, rel);
    if (fs.existsSync(file)) { pushScanned(rel); scan(file, rel, paths); }
  }
  scanOrphanComposites(projectDir, reached, pushScanned, paths);
  // a locally-called reusable workflow is ALSO scanned standalone by the
  // workflowFiles() loop, keep the caller-informed (via-chained) entry
  const viaKeys = new Set(paths.filter((p) => p.via && p.via.length).map((p) => `${p.file}:${p.line}`));
  paths = paths.filter((p) => (p.via && p.via.length) || !viaKeys.has(`${p.file}:${p.line}`));
  paths.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  // version-floor verdicts per path (GitHub: the setup-node pin in the job)
  const floors = { trusted: PUBLISH.trusted, staged: PUBLISH.staged };
  for (const p of paths) {
    if (p.nodeVersion !== undefined && p.nodeVersion !== null) {
      const below = nodePinBelowFloor(p.nodeVersion, PUBLISH.trusted.minNode);
      if (below) p.nodeBelowFloor = true;
    }
  }

  // engines.node minimum vs the shared Node floor (a maintainer publishing
  // locally on the minimum supported Node would be below both fixes' floor)
  let enginesNode = null, enginesBelowFloor = false;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    enginesNode = pkg.engines && pkg.engines.node ? String(pkg.engines.node) : null;
    const min = enginesMinimum(enginesNode);
    if (min && !versionGte(min, PUBLISH.trusted.minNode)) enginesBelowFloor = true;
  } catch { /* no package.json */ }

  // Only ever downgrades TRUSTED, so classifyAuth stays four-verdict.
  for (const p of paths) {
    const b = oidcBreakage(p);
    if (b.broken) {
      const o = PUBLISH.oidc;
      p.classification = 'BROKEN';
      p.reason = `trusted publishing (OIDC) intended (${p.idToken.via} granted, line ${p.idToken.line}),`
        + ` but actions/setup-node@${p.setupNode.ref} with \`registry-url:\` writes a dummy _authToken`
        + ` into .npmrc, so npm skips the OIDC token exchange and the publish fails`
        + ` (${shortIssue(o.issues[0])}; fixed in setup-node v${o.setupNodeFixedIn})`;
    } else if (b.note) {
      p.oidcNote = b.note;
    }
  }

  // release gate per path: GitLab/CircleCI/orphan scanners set it in place,
  // GitHub paths classify here from the threaded trigger + environment. An
  // `if:` guard is reported, never evaluated.
  for (const p of paths) {
    if (!p.gate) p.gate = classifyGate({ triggers: p.trigger, environment: p.environment });
    if (p.ifGuard) p.gate.reason += ` An \`if:\` condition guards the publish ${p.ifGuard} and was not evaluated.`;
  }
  const gates = { [GATE.DANGEROUS]: 0, [GATE.REVIEWABLE]: 0, [GATE.MANUAL]: 0, [GATE.TAG]: 0, [GATE.AUTO]: 0, [GATE.UNKNOWN]: 0 };
  for (const p of paths) gates[p.gate.class]++;

  const counts = { TRUSTED: 0, STAGED: 0, TOKEN: 0, BROKEN: 0, UNKNOWN: 0 };
  for (const p of paths) counts[p.classification]++;
  return {
    projectDir, scanned, paths, counts, gates, floors,
    cliff: PUBLISH.cliff, repo,
    enginesNode, enginesBelowFloor,
  };
}

// --- the --check verdict ---------------------------------------------------
// Exit 1 on TOKEN and BROKEN paths and on a DANGEROUS gate, each with its own
// message. `--require-gate <none|tag|manual|environment>` raises the bar for
// the remaining gates. UNKNOWN (verdict or gate) never fails; a repo with no
// publish step passes with a one-line reason, matching `allow --ci-check`.

function checkPublish(analysis, { requireGate = 'none' } = {}) {
  const failures = analysis.paths
    .filter((p) => p.classification === 'TOKEN' || p.classification === 'BROKEN')
    .map((p) => ({
      path: p,
      verdict: p.classification,
      message: p.classification === 'TOKEN' ? tokenFailureMessage(p) : brokenFailureMessage(p),
    }));
  for (const p of analysis.paths) {
    if (p.gate.class === GATE.DANGEROUS) {
      failures.push({ path: p, verdict: GATE.DANGEROUS, message: dangerousFailureMessage(p) });
    }
  }
  const bar = REQUIRE_GATE_BAR[requireGate] || 0;
  if (bar > 0) {
    for (const p of analysis.paths) {
      const rank = GATE_RANK[p.gate.class];
      if (rank !== undefined && rank < bar) {
        failures.push({ path: p, verdict: 'UNGATED', message: ungatedFailureMessage(p, requireGate) });
      }
    }
  }
  if (failures.length > 0) return { ok: false, failures, reason: null };
  const reason = analysis.paths.length === 0
    ? 'no publish steps found in CI configs, so nothing is exposed to the token cliff'
    : analysis.counts.UNKNOWN === analysis.paths.length
      ? `${analysis.counts.UNKNOWN} publish path(s) could not be classified (UNKNOWN never fails this check). Inspect them with \`npm-script-lens publish\``
      : `every classified publish path already uses trusted or staged publishing (${analysis.counts.TRUSTED} trusted, ${analysis.counts.STAGED} staged${analysis.counts.UNKNOWN ? `, ${analysis.counts.UNKNOWN} unknown` : ''})`;
  return { ok: true, failures: [], reason };
}

module.exports = {
  analyzePublish, checkPublish, renderPublish, publishJson, publishFindings,
  classifyAuth, oidcBreakage, nodePinBelowFloor, enginesMinimum, parseYamlish, detectRunPublisher,
  classifyRunsOn, idTokenGrant, repoIdentity, resolveLocalUses,
  classifyGate, readTriggers, REQUIRE_GATE_VALUES,
};
