'use strict';
const { trustLabel, driftNote } = require('./trust');
const { INERT_SKIP_FROM, skipsInertOptional, PUBLISH } = require('./npm-contract');

const RANK = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3, ERROR: 4 };
const BADGE = { HIGH: '🔴 HIGH', MEDIUM: '🟠 MEDIUM', LOW: '🟡 LOW', SAFE: '🟢 SAFE', ERROR: '⚪ ERROR' };

// results: [{ name, version, rows: [{script, command, risk, signals}], error?,
//             via?, trust?, malicious?, advisories?, base?: {version, gained} }]
function packageRisk(r) {
  if (r.error) return 'ERROR';
  if (r.rows.length === 0) return 'SAFE';
  return r.rows.reduce((a, b) => (RANK[b.risk] < RANK[a] ? b.risk : a), 'SAFE');
}

const sortRank = (r) => (r.malicious ? -1 : RANK[packageRisk(r)]);
const esc = (s) => s.replace(/\|/g, '¦');

// Suggested npm v12 allowScripts block: version-pinned entries, true only for
// packages whose scripts showed no exec/network behavior. Humans flip the
// rest after review. Known-malicious packages are always false.
function buildAllowScripts(results) {
  const allow = {};
  for (const r of results) {
    if (r.rows.length === 0 && !r.error && !r.malicious) continue;
    allow[`${r.name}@${r.version}`] = r.malicious ? false : ['SAFE', 'LOW'].includes(packageRisk(r));
  }
  return { allowScripts: allow };
}

// The suggested block is computed from THIS lockfile alone: it never reads the
// allowScripts you already have. So it is only ever offered as a replacement,
// with that said out loud, and the merge is left to `allow --write` / `sync
// --write`, which read the existing block and keep your decisions. An empty
// suggestion is not something to paste at all.
function suggestionSection(allow) {
  if (Object.keys(allow).length === 0) {
    return ['## allowScripts', '',
      'No package in this lockfile runs install scripts, so no `allowScripts` entries are needed here. '
      + 'Nothing to paste, and **if you already have an `allowScripts` block, keep it**: '
      + 'run `npm-script-lens sync --check` to see whether any of its entries have gone stale.'];
  }
  return ['## Suggested allowScripts', '',
    'Entries with risky behavior default to `false`, so review then flip the ones you trust.',
    '',
    '> This is the complete block for this lockfile, computed without reading your current one. '
    + 'Pasting it **replaces** any `allowScripts` you already have. '
    + 'To merge instead, keeping the decisions you have already made, run '
    + '`npm-script-lens allow --write` or `npm-script-lens sync --write`.',
    '',
    '```json', JSON.stringify({ allowScripts: allow }, null, 2), '```'];
}

// The package cell carries identity plus context: how it got into the tree
// (via chain) and how much to trust the publisher (trust line).
function packageCell(r) {
  const parts = [`\`${r.name}@${r.version}\``];
  if (r.malicious) parts.push(`**⛔ ${esc(r.advisories.join(', '))}**`);
  if (r.via && r.via.length > 0) parts.push(`_via ${esc(r.via.join(' → '))}_`);
  const label = trustLabel(r.trust);
  if (label) parts.push(`_${esc(label)}_`);
  return parts.join('<br>');
}

function gainedNote(r) {
  if (!r.base) return null;
  if (r.base.gained === null) return `_upgrade from ${r.base.version}: base version could not be compared_`;
  return r.base.gained.length > 0
    ? `**⚠️ gained vs ${r.base.version}:** ${r.base.gained.map((s) => `\`${esc(s)}\``).join(' ')}`
    : `_no new capabilities vs ${r.base.version}_`;
}

// The sibling of gainedNote, set by runAudit on the --diff/--since path.
const changeText = (changes) => changes.map((ch) => `${ch.field} ${ch.from} → ${ch.to}`).join(', ');

function provenanceChangeNote(r) {
  if (!r.provenanceChange) return null;
  return `**⚠️ provenance identity changed vs ${r.provenanceChange.baseVersion}:** ${esc(changeText(r.provenanceChange.changes))}`;
}

// Informational only, never a severity. See trust.repoDrift for why.
function repoDriftNote(r) {
  const note = driftNote(r.trust);
  return note ? `_ℹ️ ${esc(note)}_` : null;
}

// Trust downgrades get their own section rather than a table note: the
// downgraded package usually has no install scripts at all (axios does not),
// so it never appears in the scripted-packages table.
function trustDowngradeSection(results) {
  const hit = results.filter((r) => r.trustDowngrade);
  if (hit.length === 0) return [];
  const lines = [`## ⛔ Trust downgrade (${hit.length})`, '',
    'The resolved version sits below the highest trust tier an earlier version of its package reached '
    + '(trusted publisher > provenance > none, [npm/cli#9242](https://github.com/npm/cli/issues/9242)), '
    + 'the fingerprint of a publish from a stolen token that cannot run the maintainer\'s CI. '
    + 'pnpm >= 10.21 refuses these installs under `trust-policy=no-downgrade`.', ''];
  for (const r of hit) {
    const d = r.trustDowngrade;
    lines.push(`- \`${r.name}@${r.version}\` ${d.from} -> ${d.to}: highest prior trust ${d.from} `
      + `(\`${r.name}@${d.priorVersion}\`, published ${d.priorPublishedAt.slice(0, 10)})`);
  }
  lines.push('');
  return lines;
}

function buildReport(results, { note } = {}) {
  const scripted = results.filter((r) => r.rows.length > 0 || r.error || r.malicious);
  const clean = results.length - scripted.length;
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0, ERROR: 0 };
  let malicious = 0;
  for (const r of scripted) {
    counts[packageRisk(r)]++;
    if (r.malicious) malicious++;
  }
  const lines = ['# npm-script-lens report', ''];
  lines.push(`Audited **${results.length}** locked packages: ` +
    (malicious ? `**${malicious}** ⛔ KNOWN MALICIOUS, ` : '') +
    `**${counts.HIGH}** HIGH, **${counts.MEDIUM}** MEDIUM, **${counts.LOW}** LOW risk install scripts; ` +
    `**${counts.SAFE + clean}** with no risky install-time behavior` +
    (counts.ERROR ? `; **${counts.ERROR}** could not be fetched` : '') + '.', '');
  if (note) lines.push(note, '');
  if (scripted.length > 0) {
    lines.push('| package | script | risk | signals |', '|---|---|---|---|');
    for (const r of [...scripted].sort((a, b) => sortRank(a) - sortRank(b))) {
      const badge = r.malicious ? '⛔ MALICIOUS' : BADGE[packageRisk(r)];
      if (r.error) {
        lines.push(`| ${packageCell(r)} | — | ${BADGE.ERROR} | ${r.error} |`);
        continue;
      }
      if (r.rows.length === 0) {
        lines.push(`| ${packageCell(r)} | — | ${badge} | flagged by OSV advisory |`);
        continue;
      }
      r.rows.forEach((row, i) => {
        const cell = [];
        if (row.signals.length > 0) cell.push(row.signals.map((s) => `\`${esc(s)}\``).join('<br>'));
        if (i === 0 && gainedNote(r)) cell.push(gainedNote(r));
        if (i === 0 && provenanceChangeNote(r)) cell.push(provenanceChangeNote(r));
        if (i === 0 && repoDriftNote(r)) cell.push(repoDriftNote(r));
        lines.push(`| ${packageCell(r)} | ${row.script} | ` +
          `${r.malicious ? badge : BADGE[row.risk]} | ${cell.join('<br>') || '—'} |`);
      });
    }
    lines.push('');
  }
  lines.push(...trustDowngradeSection(results));
  lines.push(...suggestionSection(buildAllowScripts(results).allowScripts));
  lines.push('', '_HIGH = spawns processes or runs constructed code · MEDIUM = network access · LOW = fs/env only · generated by npm-script-lens_');
  return lines.join('\n');
}

// npm v12 approve-scripts gap findings (from src/v12gaps.js):
// [{ id, severity, package, version?, script?, file?, line?, fix }]
const GAP_RULES = {
  'v12-optional-gap': {
    id: 'v12-optional-gap',
    text: 'Optional dependency with install scripts is missing from allowScripts: npm approve-scripts does not surface it, but npm ci --strict-allow-scripts rejects it (npm/cli#9562)',
  },
  'v12-eglobal-risk': {
    id: 'v12-eglobal-risk',
    text: 'CI workflow installs a package with install scripts globally without --allow-scripts: npm approve-scripts fails with EGLOBAL in global contexts (npm/cli#9463)',
  },
};

function buildGapsReport(findings, { npmMajor = null, npmVersion = null } = {}) {
  const lines = ['# npm v12 approve-scripts gap check', ''];
  lines.push('Checks for two known npm v12 tooling bugs: optional dependencies with install scripts that '
    + '`npm approve-scripts` never surfaces but `npm ci --strict-allow-scripts` rejects '
    + '([npm/cli#9562](https://github.com/npm/cli/issues/9562)), and global installs in CI where '
    + '`approve-scripts` fails with EGLOBAL ([npm/cli#9463](https://github.com/npm/cli/issues/9463)).', '');
  const shownVersion = npmVersion || (npmMajor === null ? null : `${npmMajor}.x`);
  lines.push(`_Checked against your local npm ${shownVersion === null ? '(version could not be determined)' : `v${shownVersion}`}. `
    + 'These detectors track specific npm bugs. Follow each linked issue for current upstream status, '
    + 'since a fixed npm can make a detector obsolete._', '');
  lines.push(`_npm/cli#9562 (optional deps) was fixed by [PR #9597](https://github.com/npm/cli/pull/9597), `
    + `\`--strict-allow-scripts\` skips **inert** optional dependencies from npm **${INERT_SKIP_FROM.npm11}** `
    + `(and **${INERT_SKIP_FROM.npm12}** on the v12 line). `
    + (skipsInertOptional(npmVersion)
      ? 'Your npm carries that fix, so optional deps whose `os`/`cpu` exclude this platform are **not** reported below, only ones that really would install here.'
      : 'Your npm predates that fix (or its version could not be read), so every uncovered optional dep with install scripts is reported.')
    + '_', '');
  if (findings.length === 0) {
    lines.push('🟢 **No gaps found**. Every optional dependency with install scripts is covered by '
      + '`allowScripts`, and no CI workflow installs a scripted package globally without `--allow-scripts`.');
  } else {
    lines.push(`🟠 **${findings.length} gap(s) found.**`, '');
    lines.push('| check | package | where | fix |', '|---|---|---|---|');
    for (const f of findings) {
      const pkg = `\`${f.package}${f.version ? `@${f.version}` : ''}\``;
      const where = f.file ? `\`${esc(f.file)}:${f.line}\`` : `script: \`${esc(f.script)}\``;
      lines.push(`| \`${f.id}\` | ${pkg} | ${where} | ${esc(f.fix)} |`);
    }
  }
  lines.push('', '_generated by npm-script-lens audit --check-v12-gaps_');
  return lines.join('\n');
}

// A publish path that authenticates with a long-lived token (from
// src/publish.js): direct token publishing ends around January 2027, so this
// gets its own rule id, anchored to the workflow line that publishes.
const PUBLISH_RULE = {
  id: 'publish-token-cliff',
  text: 'CI publish step authenticates with a long-lived npm token. 2FA-bypass tokens lose direct publish around January 2027; migrate to trusted publishing (OIDC) or staged publishing',
};

// A trusted-publishing path broken by setup-node older than v7 writing a
// dummy _authToken: the workflow looks migrated, but the publish fails.
const PUBLISH_OIDC_RULE = {
  id: 'publish-oidc-broken',
  text: 'Trusted publishing (OIDC) is granted but actions/setup-node older than v7 with registry-url writes a dummy _authToken into .npmrc, so npm skips the OIDC token exchange and the publish fails; bump setup-node to v7 or later, drop registry-url, or strip the _authToken line',
};

// Release-gate rules (from src/publish.js): a publish reachable from a
// trigger crates.io removed from Trusted Publishing, and (opt-in via
// --require-gate) a gate weaker than the configured bar. Both anchor to the
// trigger line in the workflow file.
const PUBLISH_GATE_RULES = {
  'publish-dangerous-trigger': {
    id: 'publish-dangerous-trigger',
    text: `A CI npm publish is reachable from ${PUBLISH.gates.dangerousTriggers.join(' or ')}, triggers crates.io removed from Trusted Publishing after past CI security incidents; move the publish into its own release/tag/workflow_dispatch workflow`,
  },
  'publish-ungated': {
    id: 'publish-ungated',
    text: 'A CI npm publish runs without the release gate --require-gate demands; declare an environment: with required reviewers on the publish job, or move it behind a tag, release or workflow_dispatch trigger',
  },
};

// repo-drift is a note and must never be promoted: npm's publish flow rejects
// a provenance repository mismatch, so a live drift is a rename, not an
// attack signal.
const PROVENANCE_RULES = {
  'provenance-identity-changed': {
    id: 'provenance-identity-changed',
    text: 'The attested build identity (source repository, workflow path or ref) differs between the base and upgraded version, or provenance appeared/disappeared across the upgrade',
  },
  'provenance-repo-drift': {
    id: 'provenance-repo-drift',
    text: 'The provenance attestation names a different repository than the package declares, likely a repo rename or transfer since publish (informational, npm rejects a mismatch at publish time)',
  },
};

// A resolved version below its package's historical-max trust tier (from
// src/downgrade.js). error, not warning: the shape is precisely how the
// unpublished axios 1.14.1 / 0.30.4 credential-theft releases looked, and the
// check only runs when the user opted in.
const TRUST_DOWNGRADE_RULE = {
  id: 'trust-downgrade',
  text: 'The resolved version\'s trust tier (trusted publisher > provenance > none, npm/cli#9242) is lower than the highest tier an earlier version of the package reached, the fingerprint of a publish from a stolen token; pnpm >= 10.21 refuses this install under trust-policy=no-downgrade',
};

// An open-time execution entry (from src/hooks.js): a .vscode/tasks.json task
// with runOn: folderOpen, or a .claude/settings.json hook, code that runs
// when the folder is opened, before any install step. warning by default,
// error when the entry scores HIGH (or ships inside a dependency tarball).
const HOOK_RULE = {
  id: 'hook-auto-run',
  text: 'Editor or agent configuration runs a command automatically at open time (.vscode/tasks.json runOn: folderOpen, or a .claude/settings.json hook), so code executes when the folder is opened, with no install step involved',
};

// SARIF 2.1.0 for GitHub code scanning: one result per risky package, level
// mapped from risk, anchored to the package's line in the lockfile so alerts
// annotate the right place.
const SARIF_RULES = {
  MALICIOUS: { id: 'known-malicious-package', text: 'Package is flagged as malicious by an OSV advisory' },
  HIGH: { id: 'high-risk-install-script', text: 'Install script can spawn processes or execute dynamically-built code' },
  MEDIUM: { id: 'network-install-script', text: 'Install script can reach the network' },
  LOW: { id: 'fs-env-install-script', text: 'Install script writes files or reads environment variables' },
  ERROR: { id: 'audit-error', text: 'Package could not be fetched from the registry for auditing' },
};
const SARIF_LEVEL = { MALICIOUS: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', ERROR: 'note' };

// binding.gyp / .gypi execution channels, reported alongside the risk rules.
// A separate rule id so code-scanning can triage "this package's BUILD FILE
// runs shell commands" apart from "this package's install SCRIPT does".
const GYP_RULE = {
  id: 'gyp-exec-channel',
  text: 'binding.gyp or an included .gypi uses a gyp execution channel (command expansion, pymod_do_main, listfile, action, make_global_settings, or a Python-eval condition), and node-gyp runs it at install time',
};

function buildSarif(results, { lockPath = 'package-lock.json', lockText = '', findings = [] } = {}) {
  const uri = lockPath.replace(/\\/g, '/');
  const lines = lockText.split(/\r?\n/);
  const lineOf = (name) => {
    const i = lines.findIndex((l) => l.includes(`node_modules/${name}"`) ||
      l.includes(`"${name}@`) || l.startsWith(`${name}@`) || l.includes(`/${name}@`) || l.includes(`/${name}/`));
    return i >= 0 ? i + 1 : 1;
  };
  // v12 gap findings anchor to the workflow line that triggered them, or to
  // the package's lockfile line for optional-dep gaps
  const gapResults = findings.map((f) => ({
    ruleId: f.id,
    level: f.level || 'warning',
    message: { text: `${f.package}${f.version ? `@${f.version}` : ''}: ${f.fix}` },
    locations: [{
      physicalLocation: f.file
        ? { artifactLocation: { uri: f.file }, region: { startLine: f.line || 1 } }
        : { artifactLocation: { uri }, region: { startLine: lineOf(f.package) } },
    }],
    partialFingerprints: { gap: f.fingerprint || `${f.id}:${f.package}` },
  }));
  const sarifResults = [];
  const gypSarifResults = [];
  const provSarifResults = [];
  for (const r of results) {
    if (r.provenanceChange) {
      provSarifResults.push({
        ruleId: 'provenance-identity-changed',
        level: 'warning',
        message: { text: `${r.name}@${r.version}: provenance identity changed vs ${r.provenanceChange.baseVersion}: ${changeText(r.provenanceChange.changes)}` },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: lineOf(r.name) } } }],
        partialFingerprints: { provenance: `provenance-identity-changed:${r.name}@${r.version}` },
      });
    }
    const drift = driftNote(r.trust);
    if (drift) {
      provSarifResults.push({
        ruleId: 'provenance-repo-drift',
        level: 'note',
        message: { text: `${r.name}@${r.version}: ${drift}` },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: lineOf(r.name) } } }],
        partialFingerprints: { provenance: `provenance-repo-drift:${r.name}@${r.version}` },
      });
    }
    const gypSignals = (r.rows || []).flatMap((row) => (row.signals || []).filter((s) => s.startsWith('gyp: ')));
    if (gypSignals.length > 0) {
      gypSarifResults.push({
        ruleId: GYP_RULE.id,
        level: 'warning',
        message: { text: `${r.name}@${r.version}: ${GYP_RULE.text}. ${[...new Set(gypSignals)].join(' | ')}` },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: lineOf(r.name) } } }],
        partialFingerprints: { gyp: `gyp-exec-channel:${r.name}@${r.version}` },
      });
    }
    const risk = r.malicious ? 'MALICIOUS' : packageRisk(r);
    if (risk === 'SAFE') continue;
    const detail = r.malicious ? `Advisories: ${r.advisories.join(', ')}`
      : r.error ? r.error
        : r.rows.filter((row) => row.risk !== 'SAFE')
          .map((row) => `${row.script}: ${row.signals.join(' · ') || row.command}`).join(' | ');
    sarifResults.push({
      ruleId: SARIF_RULES[risk].id,
      level: SARIF_LEVEL[risk],
      message: { text: `${r.name}@${r.version}: ${SARIF_RULES[risk].text}. ${detail}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri },
          region: { startLine: lineOf(r.name) },
        },
      }],
      partialFingerprints: { packageVersion: `${r.name}@${r.version}` },
    });
  }
  sarifResults.push(...gypSarifResults, ...provSarifResults, ...gapResults);
  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'npm-script-lens',
          informationUri: 'https://github.com/Booyaka101/npm-script-lens',
          version: require('../package.json').version,
          rules: [...Object.values(SARIF_RULES), GYP_RULE, ...Object.values(GAP_RULES), PUBLISH_RULE, PUBLISH_OIDC_RULE, ...Object.values(PUBLISH_GATE_RULES), HOOK_RULE, ...Object.values(PROVENANCE_RULES), TRUST_DOWNGRADE_RULE].map((rule) => ({
            id: rule.id,
            shortDescription: { text: rule.text },
          })),
        },
      },
      results: sarifResults,
    }],
  };
}

// A stable, minimal, committable "receipt" of install-time behavior: sorted
// package keys -> { risk, capabilities } where capabilities are the signal
// KINDS (exec/net/fs/env/obf/bin), not the volatile human-readable strings.
// Deliberately excludes trust data (downloads, age, OSV) so the file changes
// only when a package's *behavior* changes, the git diff of this file IS the
// approval-surface change. Deterministic per tool version, so it round-trips
// through `manifest --check`.
function packageCapabilities(r) {
  const kinds = new Set();
  for (const row of r.rows) {
    for (const s of row.signals) {
      const kind = s.split(':')[0];
      if (kind !== 'ref') kinds.add(kind);
    }
  }
  return [...kinds].sort();
}

function buildManifest(results, { deep = false } = {}) {
  const packages = {};
  const errors = [];
  for (const r of results) {
    const key = `${r.name}@${r.version}`;
    if (r.error) { errors.push(key); continue; }
    const capabilities = packageCapabilities(r);
    if (capabilities.length === 0) continue; // no install-time behavior, omit
    packages[key] = { risk: packageRisk(r), capabilities };
  }
  const sorted = {};
  for (const key of Object.keys(packages).sort()) sorted[key] = packages[key];
  const manifest = { tool: 'npm-script-lens', version: require('../package.json').version };
  if (deep) manifest.deep = true;
  manifest.packages = sorted;
  return { manifest, errors };
}

const serializeManifest = (manifest) => `${JSON.stringify(manifest, null, 2)}\n`;

// Human-readable drift between a committed manifest and a freshly built one.
function diffManifests(oldM, newM) {
  const changes = [];
  if ((oldM.version || '?') !== newM.version) {
    changes.push(`tool ${oldM.version || '?'} → ${newM.version}, detector changed, re-review`);
  }
  if (Boolean(oldM.deep) !== Boolean(newM.deep)) {
    changes.push(`deep mode ${Boolean(oldM.deep)} → ${Boolean(newM.deep)}`);
  }
  const oldP = oldM.packages || {}, newP = newM.packages || {};
  const cap = (e) => (e && e.capabilities ? e.capabilities.join(' ') : '');
  for (const key of [...new Set([...Object.keys(oldP), ...Object.keys(newP)])].sort()) {
    if (!(key in oldP)) changes.push(`+ ${key}  ${newP[key].risk} [${cap(newP[key])}]`);
    else if (!(key in newP)) changes.push(`- ${key}  (no longer has install-time behavior)`);
    else if (JSON.stringify(oldP[key]) !== JSON.stringify(newP[key])) {
      changes.push(`~ ${key}  ${oldP[key].risk} [${cap(oldP[key])}] → ${newP[key].risk} [${cap(newP[key])}]`);
    }
  }
  return changes;
}

// A self-contained, shareable HTML dashboard, no external assets, works
// offline, one file you can email or attach to a security review.
const htmlEsc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const HTML_BADGE = {
  HIGH: ['#b91c1c', '🔴 HIGH'], MEDIUM: ['#c2410c', '🟠 MEDIUM'], LOW: ['#a16207', '🟡 LOW'],
  SAFE: ['#15803d', '🟢 SAFE'], ERROR: ['#57534e', '⚪ ERROR'], MALICIOUS: ['#7f1d1d', '⛔ MALICIOUS'],
};

function buildHtml(results, { note, title = 'npm-script-lens report' } = {}) {
  const scripted = results.filter((r) => r.rows.length > 0 || r.error || r.malicious);
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0, ERROR: 0 };
  let malicious = 0;
  for (const r of scripted) { counts[packageRisk(r)]++; if (r.malicious) malicious++; }
  const clean = results.length - scripted.length;
  const rows = [...scripted].sort((a, b) => sortRank(a) - sortRank(b)).map((r) => {
    const risk = r.malicious ? 'MALICIOUS' : packageRisk(r);
    const [color, label] = HTML_BADGE[risk] || HTML_BADGE.ERROR;
    const signals = r.error ? htmlEsc(r.error)
      : r.rows.flatMap((row) => row.signals).map((s) => `<code>${htmlEsc(s)}</code>`).join(' ') || '—';
    const via = r.via && r.via.length ? `<div class="via">via ${htmlEsc(r.via.join(' → '))}</div>` : '';
    const trust = trustLabel(r.trust) ? `<div class="trust">${htmlEsc(trustLabel(r.trust))}</div>` : '';
    const provChange = r.provenanceChange
      ? `<div class="trust">⚠️ provenance identity changed vs ${htmlEsc(r.provenanceChange.baseVersion)}: ${htmlEsc(changeText(r.provenanceChange.changes))}</div>` : '';
    const drift = driftNote(r.trust) ? `<div class="trust">ℹ️ ${htmlEsc(driftNote(r.trust))}</div>` : '';
    return `<tr>
      <td><strong>${htmlEsc(r.name)}</strong>@${htmlEsc(r.version)}${via}${trust}${provChange}${drift}</td>
      <td><span class="badge" style="background:${color}">${label}</span></td>
      <td>${signals}</td></tr>`;
  }).join('\n');
  const allow = buildAllowScripts(results).allowScripts;
  const suggestion = Object.keys(allow).length === 0
    ? '<h2 style="font-size:16px">allowScripts</h2>\n<p>No package in this lockfile runs install scripts, so no <code>allowScripts</code> entries are needed here. '
      + 'If you already have a block, keep it and run <code>npm-script-lens sync --check</code> to find stale entries.</p>'
    : '<h2 style="font-size:16px">Suggested allowScripts</h2>\n'
      + '<p>The complete block for this lockfile, computed without reading your current one. Pasting it <strong>replaces</strong> any '
      + '<code>allowScripts</code> you already have; <code>npm-script-lens allow --write</code> or <code>sync --write</code> merge instead, '
      + 'keeping decisions you have already made.</p>\n'
      + `<pre>${htmlEsc(JSON.stringify({ allowScripts: allow }, null, 2))}</pre>`;
  const stat = (n, l, c) => `<div class="stat"><div class="n" style="color:${c}">${n}</div><div class="l">${l}</div></div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEsc(title)}</title>
<style>
:root{color-scheme:light dark}
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#fafaf9;color:#1c1917}
@media(prefers-color-scheme:dark){body{background:#0c0a09;color:#e7e5e4}tr:nth-child(even){background:#1c1917}code{background:#292524}pre{background:#1c1917}.card{background:#111}}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#78716c;margin:0 0 24px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 24px}
.card{background:#fff;border:1px solid #e7e5e4;border-radius:10px}
.stat{flex:1;min-width:90px;text-align:center;padding:14px;border:1px solid #e7e5e4;border-radius:10px}
.stat .n{font-size:26px;font-weight:700}.stat .l{font-size:12px;color:#78716c;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;margin:0 0 24px}
th,td{text-align:left;padding:10px 12px;vertical-align:top;border-bottom:1px solid #e7e5e4}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#78716c}
tr:nth-child(even){background:#f5f5f4}
.badge{color:#fff;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
code{background:#f5f5f4;padding:1px 5px;border-radius:4px;font-size:12px}
.via,.trust{font-size:12px;color:#78716c;margin-top:2px}
pre{background:#f5f5f4;padding:14px;border-radius:10px;overflow:auto;font-size:13px}
footer{color:#78716c;font-size:12px;margin-top:24px}
</style></head><body><div class="wrap">
<h1>${htmlEsc(title)}</h1>
<p class="sub">Audited <strong>${results.length}</strong> locked packages${note ? ` · ${htmlEsc(note.replace(/[_`*]/g, ''))}` : ''}</p>
<div class="stats">
${malicious ? stat(malicious, 'malicious', '#7f1d1d') : ''}
${stat(counts.HIGH, 'high', '#b91c1c')}${stat(counts.MEDIUM, 'medium', '#c2410c')}${stat(counts.LOW, 'low', '#a16207')}${stat(counts.SAFE + clean, 'clean', '#15803d')}${counts.ERROR ? stat(counts.ERROR, 'errors', '#57534e') : ''}
</div>
${scripted.length ? `<table><thead><tr><th>package</th><th>risk</th><th>install-script signals</th></tr></thead><tbody>\n${rows}\n</tbody></table>` : '<p>🟢 No package has risky install-time behavior.</p>'}
${suggestion}
<footer>generated by npm-script-lens · HIGH = spawns processes or runs constructed code · MEDIUM = network · LOW = fs/env</footer>
</div></body></html>
`;
}

module.exports = {
  buildReport, buildHtml, buildAllowScripts, buildSarif, buildManifest, serializeManifest, diffManifests, packageRisk,
  buildGapsReport, BADGE,
};
