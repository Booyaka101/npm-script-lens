'use strict';
// Everything a publish path looks like to a human: the failure messages the
// --check gate prints, the rendered report, the --json shape and the SARIF
// findings. Analysis lives in ../publish.js; nothing here decides a verdict.
const { PUBLISH } = require('../npm-contract');
const { shortIssue, registryHost } = require('./refs');
const {
  GATE, describeEvent, dangerousTriggers, triggerAnchor, GATE_RANK, REQUIRE_GATE_BAR,
} = require('./gates');

function dangerousFailureMessage(p) {
  const g = PUBLISH.gates;
  const at = triggerAnchor(p);
  return `${p.file}:${p.line} publishes from ${dangerousTriggers(p).names} (${at.file}:${at.line}),`
    + ` a trigger crates.io removed from Trusted Publishing (${g.cratesio.source}): "${g.cratesio.quote}"`
    + ' Move the publish into its own workflow triggered by `release`, a tag push or `workflow_dispatch`.';
}

function ungatedFailureMessage(p, requireGate) {
  const g = PUBLISH.gates;
  return `${p.file}:${p.line} publish gate is ${p.gate.class}, below the --require-gate ${requireGate} bar.`
    + ` Declare \`environment:\` on job "${p.job}" and set required reviewers on it`
    + ` (PyPI: "${g.pypi.quote.split(',')[0]}"), or move the publish behind a stronger trigger.`;
}
function tokenFailureMessage(p) {
  return `${p.file}:${p.line} publishes with a long-lived token (\`${p.tool}\`, ${p.token ? p.token.key : 'token'})`
    + `. 2FA-bypass tokens lose direct publish around ${PUBLISH.cliff.date} (${PUBLISH.cliff.changelog}).`
    + ` Migrate to ${p.runner && p.runner.kind === 'self-hosted' ? `staged publishing (\`${PUBLISH.staged.commands.publish}\` + \`${PUBLISH.staged.commands.approve}\`), since trusted publishing does not support this runner` : 'trusted publishing (OIDC) or staged publishing'}.`;
}

function brokenFailureMessage(p) {
  const o = PUBLISH.oidc;
  return `${p.file}:${p.line} intends trusted publishing (OIDC) but actions/setup-node@${p.setupNode.ref}`
    + ` with \`registry-url:\` writes a dummy _authToken that blocks the OIDC token exchange`
    + ` (${shortIssue(o.issues[0])}). Bump setup-node to v${Number(o.setupNodeFixedIn.split('.')[0])} or later`
    + ` (fixed in ${o.setupNodeFixedIn}: ${o.fixRelease}).`;
}

// --- rendering -------------------------------------------------------------

// The npmjs.com side of trusted publishing, pre-filled from the repo. The
// exact fields the settings form asks for, in its order.
function checklistLines(analysis, p) {
  const t = PUBLISH.trusted;
  const repo = analysis.repo;
  const lines = ['npmjs.com trusted-publisher settings (package Settings → Trusted publisher):'];
  if (p.provider === 'github') {
    lines.push(`  GitHub organization or user: ${repo ? repo.owner : '<your GitHub org or username>'}`);
    lines.push(`  repository:                  ${repo ? repo.repo : '<repository name>'}`);
    lines.push(`  workflow filename:           ${p.workflowFile}   (with its extension, exactly as on disk)`);
    lines.push(`  environment:                 ${p.environment ? p.environment : '(the job declares none, leave blank)'}`);
  } else if (p.provider === 'gitlab') {
    lines.push(`  GitLab namespace:            ${repo ? repo.owner : '<your GitLab group or username>'}`);
    lines.push(`  project:                     ${repo ? repo.repo : '<project name>'}`);
    lines.push(`  CI file:                     ${p.workflowFile}   (and \`id_tokens\` audience \`${t.gitlabAudience}\` in the job)`);
  } else {
    lines.push(`  CircleCI organization:       ${repo ? repo.owner : '<your CircleCI org>'}`);
    lines.push(`  project:                     ${repo ? repo.repo : '<project name>'}`);
    lines.push(`  config file:                 ${p.workflowFile}   (the OIDC token arrives as \`${t.circleciTokenVar}\`)`);
  }
  lines.push(`  allowed actions:             npm publish${p.tool === PUBLISH.staged.commands.publish ? ' and npm stage publish' : '   (also allow "npm stage publish" if you plan to stage releases)'}`);
  return lines;
}

function floorWarning(p) {
  const t = PUBLISH.trusted, s = PUBLISH.staged;
  if (!p.nodeBelowFloor) return null;
  return `⚠️  node-version ${p.nodeVersion}${p.nodeVersionLine ? ` (${p.nodeVersionFile || p.file}:${p.nodeVersionLine})` : ''} is below the Node ${t.minNode} floor, which blocks BOTH fixes: `
    + `trusted publishing needs npm >= ${t.minNpm} and Node >= ${t.minNode}, staged publishing needs npm >= ${s.minNpm} and Node >= ${s.minNode}. `
    + `Bump setup-node to >= ${t.minNode} before either migration can work.`;
}

// The YAML patch for a GitHub TOKEN path: grant id-token, drop the token env.
function tokenFixLines(analysis, p) {
  const t = PUBLISH.trusted, s = PUBLISH.staged;
  const lines = [];
  if (p.runner && p.runner.kind === 'self-hosted') {
    lines.push(`fix for ${p.file}:${p.line}, trusted publishing is UNAVAILABLE for this job:`);
    lines.push(`  \`runs-on: ${p.runner.label}\` is not a GitHub-hosted runner, and the npm docs support only`);
    lines.push(`  ${t.providers.join(', ')}:`);
    lines.push(`  "${t.selfHostedQuote}"`);
    lines.push('  Staged publishing is the survivable path here:');
    lines.push(`    replace \`${p.tool}\` with \`${s.commands.publish}\`   (needs npm >= ${s.minNpm} and Node >= ${s.minNode})`);
    lines.push(`    a maintainer then approves with 2FA: \`${s.commands.approve}\`  (\`${s.commands.list}\` shows the stage-id)`);
    if (p.token) lines.push(`    the ${p.token.key} secret can then be retired, since staging needs no bypass-2FA token scope.`);
    return lines;
  }
  lines.push(`fix for ${p.file}:${p.line}, switch to trusted publishing (OIDC):`);
  if (p.provider === 'github') {
    const viaChain = p.via && p.via.length ? p.via : null;
    lines.push(`  add to the \`${p.job}\` job (or the workflow top level) in ${viaChain ? viaChain[0].file : p.file}:`);
    lines.push('    + permissions:');
    lines.push('    +   id-token: write');
    if (viaChain) lines.push('    (a composite action cannot declare `permissions`, so the grant must live on the calling job)');
    if (p.token && p.token.key !== '_authToken') {
      lines.push(`  remove the token from the publish step (${p.via && p.via.length ? `${p.file}:` : 'line '}${p.token.line}):`);
      lines.push('    - env:');
      lines.push(`    -   ${p.token.key}: ${p.token.value || '${{ secrets.NPM_TOKEN }}'}`);
    } else if (p.token) {
      lines.push(`  remove the .npmrc write containing _authToken (line ${p.token.line}); OIDC needs no token in .npmrc`);
    }
    lines.push(`  the job needs npm >= ${t.minNpm} and Node >= ${t.minNode} (Node's bundled npm may be older than ${t.minNpm}, so add \`npm install -g npm@latest\` before publishing)`);
  } else if (p.provider === 'gitlab') {
    lines.push(`  add to the \`${p.job}\` job in ${p.file}:`);
    lines.push('    + id_tokens:');
    lines.push('    +   NPM_ID_TOKEN:');
    lines.push(`    +     aud: ${t.gitlabAudience}`);
    if (p.token) lines.push(`  remove the ${p.token.key} variable (line ${p.token.line})`);
    lines.push(`  the job needs npm >= ${t.minNpm} and Node >= ${t.minNode}; trusted publishing supports GitLab.com shared runners only`);
  } else {
    lines.push(`  configure the trusted publisher on npmjs.com, and the OIDC token then arrives as \`${t.circleciTokenVar}\` (CircleCI cloud only)`);
    if (p.token) lines.push(`  remove the ${p.token.key} environment entry (line ${p.token.line})`);
    lines.push(`  the job needs npm >= ${t.minNpm} and Node >= ${t.minNode}`);
  }
  return lines;
}

// The three ways out, anchored to the setup-node step that caused it.
function brokenFixLines(p) {
  const o = PUBLISH.oidc;
  const sn = p.setupNode;
  const vMaj = `v${Number(o.setupNodeFixedIn.split('.')[0])}`;
  return [
    `fix for ${p.file}:${p.line}, any one of these restores the OIDC exchange:`,
    `  bump actions/setup-node to @${vMaj} or later (${sn.file}:${sn.line}). v${o.setupNodeFixedIn} removed the dummy NODE_AUTH_TOKEN export (PR #1558)`,
    `  or drop \`registry-url:\` (${sn.file}:${sn.registryLine}) and set the registry yourself: \`- run: npm config set registry https://${registryHost(sn.registryUrl)}/\``,
    `  or strip the line setup-node wrote, after the setup-node step: \`- run: sed -i '/_authToken/d' "$NPM_CONFIG_USERCONFIG"\``,
  ];
}

function renderPublish(analysis) {
  const lines = [];
  const { paths, counts } = analysis;
  lines.push(`publish paths (${paths.length})`);
  for (const p of paths) {
    const where = `${p.file}:${p.line}`;
    const ctx = [p.job ? `job ${p.job}` : null, p.runner && p.runner.label ? p.runner.label : null].filter(Boolean).join(' · ');
    lines.push(`  ${p.classification.padEnd(8)}  ${where}  ${p.tool}${ctx ? `   [${ctx}]` : ''}`);
    lines.push(`            ${p.reason}`);
    if (p.oidcNote) lines.push(`            ⚠️  ${p.oidcNote}`);
    for (const v of p.via || []) {
      const vctx = [v.job ? `job ${v.job}` : null, v.step ? `step "${v.step}"` : null].filter(Boolean).join(', ');
      lines.push(`            via ${v.file}:${v.line}${vctx ? ` (${vctx})` : ''}`);
    }
    if (p.trigger) {
      const at = triggerAnchor(p);
      lines.push(`            trigger: ${p.trigger.events.map(describeEvent).join(', ')}   (${at.file}:${at.line})`);
    } else {
      lines.push('            trigger: not determinable from this file');
    }
    lines.push(`            gate:    ${p.gate.class}: ${p.gate.reason}`);
    if (p.provider === 'github' && p.gate.class === GATE.AUTO) {
      const jobAt = p.jobLine ? ` (${p.jobFile && p.jobFile !== p.file ? `${p.jobFile}:` : 'line '}${p.jobLine})` : '';
      // one logical line: src/format.js reflows it to the terminal, and
      // hand-wrapping here would fight that and go ragged
      lines.push(`            fix:     add \`environment: release\` to job "${p.job}"${jobAt} and set required reviewers on it`
        + ` (PyPI: "${PUBLISH.gates.pypi.quote.split(',')[0]}");`
        + ' or move to `on: release: types: [published]`; or publish with'
        + ` \`${PUBLISH.staged.commands.publish}\` + \`${PUBLISH.staged.commands.approve}\`.`);
    }
    if (p.provider === 'github' && p.gate.class === GATE.DANGEROUS) {
      const at = triggerAnchor(p);
      lines.push(`            fix:     remove ${dangerousTriggers(p).names} from on: (${at.file}:${at.line}), or move the publish into its own`
        + ' workflow triggered by `release`, a tag push or `workflow_dispatch`.');
    }
  }
  if (paths.length === 0) {
    lines.push('  (none; scanned .github/workflows, .github/actions/**/action.yml, .gitlab-ci.yml and .circleci/config.yml)');
    lines.push('');
    lines.push(`nothing is exposed to npm's ${analysis.cliff.date} token cliff: no publish steps in CI.`);
    return lines.join('\n');
  }
  lines.push('');
  if (counts.TOKEN > 0) {
    lines.push(`⛔ ${counts.TOKEN} TOKEN publish path${counts.TOKEN === 1 ? '' : 's'}. Direct token publishing stops working around ${analysis.cliff.date}.`);
    lines.push(`   github.blog (2026-07-31): "${analysis.cliff.quote}"`);
    lines.push('');
    for (const p of paths.filter((x) => x.classification === 'TOKEN')) {
      lines.push(...tokenFixLines(analysis, p));
      const floor = floorWarning(p);
      if (floor) lines.push(`  ${floor}`);
      lines.push('');
      if (!(p.runner && p.runner.kind === 'self-hosted')) {
        lines.push(...checklistLines(analysis, p));
        lines.push('');
      }
    }
  }
  if (counts.BROKEN > 0) {
    const o = PUBLISH.oidc;
    lines.push(`⛔ ${counts.BROKEN} BROKEN publish path${counts.BROKEN === 1 ? '' : 's'}. id-token: write is granted, but setup-node older than v${o.setupNodeFixedIn} with \`registry-url:\` writes a dummy _authToken, so the publish fails.`);
    lines.push(`   ${shortIssue(o.issues[0])}: "${o.quote}"`);
    lines.push('');
    for (const p of paths.filter((x) => x.classification === 'BROKEN')) {
      lines.push(...brokenFixLines(p));
      const floor = floorWarning(p);
      if (floor) lines.push(`  ${floor}`);
      lines.push('');
      // BROKEN paths still intend OIDC, so the npmjs.com side still applies
      lines.push(...checklistLines(analysis, p));
      lines.push('');
    }
  }
  if (analysis.gates && analysis.gates[GATE.DANGEROUS] > 0) {
    const g = PUBLISH.gates;
    const n = analysis.gates[GATE.DANGEROUS];
    lines.push(`⛔ ${n} publish path${n === 1 ? '' : 's'} reachable from ${g.dangerousTriggers.map((t) => `\`${t}\``).join(' / ')}. crates.io removed both triggers from Trusted Publishing (${g.cratesio.source}):`);
    lines.push(`   "${g.cratesio.quote}"`);
    lines.push('');
  }
  if (counts.TOKEN === 0 && counts.BROKEN === 0) {
    lines.push(`🟢 no TOKEN publish paths. Nothing here relies on direct token publishing (which ends around ${analysis.cliff.date}).`);
    for (const p of paths.filter((x) => x.nodeBelowFloor)) {
      const floor = floorWarning(p);
      if (floor) lines.push(`  ${floor}`);
    }
  }
  if (analysis.enginesBelowFloor) {
    lines.push(`note: package.json engines.node is \`${analysis.enginesNode}\`, and a maintainer publishing locally on the minimum supported Node is below the ${PUBLISH.trusted.minNode} floor both trusted and staged publishing require.`);
  }
  return lines.join('\n').replace(/\n+$/, '');
}

// The exact shape `publish --json` emits.
function publishJson(analysis) {
  return {
    cliff: { date: analysis.cliff.date, changelog: analysis.cliff.changelog },
    floors: {
      trusted: { npm: PUBLISH.trusted.minNpm, node: PUBLISH.trusted.minNode },
      staged: { npm: PUBLISH.staged.minNpm, node: PUBLISH.staged.minNode },
    },
    counts: analysis.counts,
    gates: analysis.gates,
    paths: analysis.paths.map((p) => ({
      file: p.file, line: p.line, provider: p.provider, job: p.job, tool: p.tool,
      classification: p.classification, reason: p.reason,
      runner: p.runner ? { label: p.runner.label, kind: p.runner.kind } : null,
      environment: p.environment || null,
      trigger: p.trigger
        ? { file: p.trigger.file, events: p.trigger.events.map((e) => ({ event: e.event, filters: e.filters, line: e.line })) }
        : null,
      gate: { class: p.gate.class, reason: p.gate.reason, environment: p.environment || null },
      nodeVersion: p.nodeVersion === undefined ? null : p.nodeVersion,
      nodeBelowFloor: Boolean(p.nodeBelowFloor),
      setupNode: p.setupNode || null,
      oidcNote: p.oidcNote || null,
      via: p.via || [],
    })),
    repo: analysis.repo,
    engines: { node: analysis.enginesNode, belowFloor: analysis.enginesBelowFloor },
  };
}

// TOKEN, BROKEN and gate findings in the shape reporter.buildSarif consumes.
// publish-dangerous-trigger (error) always; publish-ungated (warning) only
// when --require-gate raises the bar. Both anchor to the real trigger line.
function publishFindings(analysis, { requireGate = 'none' } = {}) {
  const findings = analysis.paths
    .filter((p) => p.classification === 'TOKEN' || p.classification === 'BROKEN')
    .map((p) => {
      const id = p.classification === 'TOKEN' ? 'publish-token-cliff' : 'publish-oidc-broken';
      return {
        id,
        severity: 'error',
        level: 'error',
        package: p.tool,
        file: p.file,
        line: p.line,
        fix: p.classification === 'TOKEN' ? tokenFailureMessage(p) : brokenFailureMessage(p),
        fingerprint: `${id}:${p.file}:${p.line}`,
      };
    });
  for (const p of analysis.paths) {
    if (p.gate.class === GATE.DANGEROUS) {
      const at = triggerAnchor(p);
      findings.push({
        id: 'publish-dangerous-trigger', severity: 'error', level: 'error',
        package: p.tool, file: at.file, line: at.line,
        fix: dangerousFailureMessage(p),
        fingerprint: `publish-dangerous-trigger:${at.file}:${at.line}`,
      });
    }
  }
  const bar = REQUIRE_GATE_BAR[requireGate] || 0;
  if (bar > 0) {
    for (const p of analysis.paths) {
      const rank = GATE_RANK[p.gate.class];
      if (rank !== undefined && rank < bar) {
        const at = triggerAnchor(p);
        findings.push({
          id: 'publish-ungated', severity: 'warning', level: 'warning',
          package: p.tool, file: at.file, line: at.line,
          fix: ungatedFailureMessage(p, requireGate),
          fingerprint: `publish-ungated:${at.file}:${at.line}`,
        });
      }
    }
  }
  return findings;
}

module.exports = {
  renderPublish, publishJson, publishFindings, checklistLines, floorWarning,
  tokenFixLines, brokenFixLines,
  dangerousFailureMessage, ungatedFailureMessage, tokenFailureMessage, brokenFailureMessage,
};
