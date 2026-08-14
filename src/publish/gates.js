'use strict';
// Who can cause this publish path to run TODAY? Auth classification answers
// "will it publish after the cliff"; the gate answers the ChainDrop question:
// an account takeover lands a commit, and the repo's own release workflow
// builds, signs and publishes it. Gate classes, the banned trigger names and
// the registry-precedent quotes live in PUBLISH.gates, nowhere else.

const { PUBLISH } = require('../npm-contract');
const { child, unquote, commandLines } = require('./yaml');

const GATE = PUBLISH.gates.classes;

// The workflow's `on:` node, read tolerantly. parseYamlish keeps `on` as a
// literal key (a real YAML 1.1 parser would turn it into `true`, one reason
// this module has no YAML dependency). Handles the scalar (`on: push`), the
// flow list (`on: [push, pull_request]`), the block list and the block map,
// plus the quoted `"on":` key form via unquote.
function readTriggers(root, rel) {
  const on = child(root, 'on');
  if (!on) return null;
  const events = [];
  const add = (event, line, filters) => { if (event) events.push({ event, filters: filters || null, line }); };
  if (on.value !== null) {
    const v = unquote(on.value);
    if (v.startsWith('[')) for (const e of v.replace(/^\[|\]$/g, '').split(',')) add(unquote(e), on.line);
    else add(v, on.line);
  }
  for (const c of on.children) {
    if (c.item && c.value) { add(unquote(c.value), c.line); continue; }
    if (!c.key) continue;
    let filters = null;
    for (const fk of ['branches', 'branches-ignore', 'tags', 'tags-ignore', 'types']) {
      const fn = child(c, fk);
      if (!fn) continue;
      const vals = [];
      if (fn.value !== null) {
        const v = unquote(fn.value);
        if (v.startsWith('[')) vals.push(...v.replace(/^\[|\]$/g, '').split(',').map((s) => unquote(s)).filter(Boolean));
        else vals.push(v);
      }
      for (const l of fn.children) if (l.item && l.value) vals.push(unquote(l.value));
      if (vals.length > 0) { filters = filters || {}; filters[fk] = vals; }
    }
    add(c.key, c.line, filters);
  }
  return events.length > 0 ? { events, file: rel } : null;
}

// 'push → branches: [main]' for the report and the failure messages.
function describeEvent(ev) {
  if (!ev.filters) return ev.event;
  const parts = Object.entries(ev.filters).map(([k, vals]) => `${k}: [${vals.join(', ')}]`);
  return `${ev.event} → ${parts.join(', ')}`;
}

// The gate tier one event reaches; null = nothing this reader can classify
// (workflow_call resolves through callers, unrecognized events stay unguessed).
// GitHub push semantics: defining only tags/tags-ignore means branch pushes do
// not run the workflow, so that is the tag-only shape.
function eventGate(ev) {
  if (PUBLISH.gates.dangerousTriggers.includes(ev.event)) return GATE.DANGEROUS;
  if (ev.event === 'push') {
    const f = ev.filters || {};
    const tagsOnly = (f.tags || f['tags-ignore']) && !(f.branches || f['branches-ignore']);
    return tagsOnly ? GATE.TAG : GATE.AUTO;
  }
  if (['pull_request', 'schedule', 'merge_group'].includes(ev.event)) return GATE.AUTO;
  if (['workflow_dispatch', 'release'].includes(ev.event)) return GATE.MANUAL;
  return null;
}

// One gate class per path. DANGEROUS beats REVIEWABLE; otherwise a declared
// environment wins (the one hook GitHub offers for required reviewers, the
// protection PyPI's security model names); otherwise the WEAKEST tier any
// trigger reaches. UNKNOWN never affects an exit code.
function classifyGate({ triggers, environment } = {}) {
  const g = PUBLISH.gates;
  const events = (triggers && triggers.events) || [];
  const dangerous = events.filter((e) => g.dangerousTriggers.includes(e.event));
  if (dangerous.length > 0) {
    return {
      class: GATE.DANGEROUS,
      // the quote itself is printed once, in the ⛔ summary block
      reason: `reachable from \`${dangerous.map((e) => e.event).join('\`, \`')}\`, ${dangerous.length === 1 ? 'a trigger' : 'triggers'} crates.io removed from Trusted Publishing (${g.cratesio.source})`,
    };
  }
  if (environment) {
    return {
      class: GATE.REVIEWABLE,
      reason: `job declares environment "${environment}"; verify required reviewers are configured on it (protection rules are not visible from the working tree)`,
    };
  }
  const tiered = events.map((e) => ({ e, tier: eventGate(e) })).filter((t) => t.tier !== null);
  const of = (tier) => tiered.filter((t) => t.tier === tier).map((t) => t.e);
  const auto = of(GATE.AUTO);
  if (auto.length > 0) {
    const ev = auto[0];
    const what = ev.event === 'push'
      ? (ev.filters && ev.filters.branches
        ? `any commit that lands on ${ev.filters.branches.join(' or ')} publishes to npm`
        : 'any push to any branch publishes to npm')
      : ev.event === 'schedule'
        ? 'the schedule publishes to npm with no human in the loop'
        : `any \`${ev.event}\` run publishes to npm`;
    return { class: GATE.AUTO, reason: `${what}. The job declares no environment:, so GitHub cannot require an approval.` };
  }
  if (of(GATE.TAG).length > 0) {
    return { class: GATE.TAG, reason: 'only a pushed tag reaches this job; a tag push needs write access, but nobody approves the publish itself' };
  }
  const manual = of(GATE.MANUAL);
  if (manual.length > 0) {
    return { class: GATE.MANUAL, reason: `only ${manual.map((e) => `\`${e.event}\``).join(' and ')} reach${manual.length === 1 ? 'es' : ''} this job, each a deliberate human action` };
  }
  if (events.length > 0) {
    return { class: GATE.UNKNOWN, reason: `the effective trigger cannot be determined: \`${events.map((e) => e.event).join('\`, \`')}\` ${events.length === 1 ? 'is' : 'are'} resolved by callers or events outside this file` };
  }
  return { class: GATE.UNKNOWN, reason: 'no workflow trigger is visible for this path, so the gate cannot be determined' };
}

// The GitLab equivalents this reader can see: an `environment:` key (GitLab
// environments carry approval rules, the REVIEWABLE analogue), a job-level
// `when: manual`, and `rules:`/`only:` pinning the job to `$CI_COMMIT_TAG` (or
// `only: [tags]`). Anything else stays UNKNOWN, never a guess.
function gitlabGate(job, rel) {
  const envNode = child(job, 'environment');
  const environment = envNode
    ? (envNode.value !== null ? unquote(envNode.value) : (child(envNode, 'name') && unquote(child(envNode, 'name').value || '')) || null)
    : null;
  let trigger = null, tier = null;
  const whenNode = child(job, 'when');
  if (whenNode && whenNode.value !== null && unquote(whenNode.value) === 'manual') {
    trigger = { events: [{ event: 'when: manual', filters: null, line: whenNode.line }], file: rel };
    tier = { class: GATE.MANUAL, reason: 'the job runs only when a person plays it (`when: manual`)' };
  } else {
    let tagLine = null, via = null;
    for (const item of ((child(job, 'rules') || { children: [] }).children)) {
      const cond = child(item, 'if');
      if (cond && /\$CI_COMMIT_TAG\b/.test(String(cond.value || ''))) { tagLine = cond.line; via = 'rules: if $CI_COMMIT_TAG'; break; }
    }
    if (tagLine === null) {
      for (const l of commandLines(child(job, 'only'))) {
        const v = unquote(l.text);
        if (v === 'tags' || /\$CI_COMMIT_TAG\b/.test(v)) { tagLine = l.line; via = `only: ${v}`; break; }
      }
    }
    if (tagLine !== null) {
      trigger = { events: [{ event: via, filters: null, line: tagLine }], file: rel };
      tier = { class: GATE.TAG, reason: 'only a tag pipeline reaches this job; a tag push needs write access, but nobody approves the publish itself' };
    }
  }
  const gate = environment
    ? { class: GATE.REVIEWABLE, reason: `job declares environment "${environment}"; verify approval rules are configured on it (protection rules are not visible from the working tree)` }
    : tier || { class: GATE.UNKNOWN, reason: 'no `environment:`, `when: manual` or tag-only `rules:`/`only:` is visible on this job, so the gate cannot be determined' };
  return { gate, trigger, environment };
}

// The one human gate CircleCI expresses in config: an `approval`-type job
// upstream of the publish job in the same workflow. Walks the requires graph
// transitively; anything else stays UNKNOWN (schedules and filters are not
// read, so no guessing).
function circleciApproval(root, jobName) {
  const workflows = child(root, 'workflows');
  if (!workflows) return null;
  for (const wf of workflows.children) {
    if (!wf.key || wf.key === 'version') continue;
    const jobsNode = child(wf, 'jobs');
    if (!jobsNode) continue;
    const entries = {};
    for (const it of jobsNode.children) {
      if (!it.item) continue;
      if (it.value) { entries[unquote(it.value)] = { requires: [], approval: false, line: it.line }; continue; }
      const named = it.children[0];
      if (!named || !named.key) continue;
      const type = child(named, 'type');
      const reqNode = child(named, 'requires');
      const requires = [];
      if (reqNode && reqNode.value !== null) {
        const v = unquote(reqNode.value);
        if (v.startsWith('[')) requires.push(...v.replace(/^\[|\]$/g, '').split(',').map((s) => unquote(s)).filter(Boolean));
        else requires.push(v);
      }
      for (const l of (reqNode ? reqNode.children : [])) if (l.item && l.value) requires.push(unquote(l.value));
      entries[named.key] = { requires, approval: Boolean(type && unquote(type.value || '') === 'approval'), line: named.line };
    }
    if (!entries[jobName]) continue;
    const seen = new Set();
    const queue = [...entries[jobName].requires];
    while (queue.length > 0) {
      const name = queue.shift();
      if (seen.has(name)) continue;
      seen.add(name);
      const e = entries[name];
      if (!e) continue;
      if (e.approval) return { workflow: wf.key, job: name, line: e.line };
      queue.push(...e.requires);
    }
    return { workflow: wf.key, job: null, line: null };
  }
  return null;
}

// How high a --require-gate bar each class clears.
const REQUIRE_GATE_VALUES = ['none', 'tag', 'manual', 'environment'];
const GATE_RANK = { [GATE.AUTO]: 1, [GATE.TAG]: 2, [GATE.MANUAL]: 3, [GATE.REVIEWABLE]: 4 };
const REQUIRE_GATE_BAR = { none: 0, tag: 2, manual: 3, environment: 4 };

// The banned events reaching a path, plus the name list the messages print.
function dangerousTriggers(p) {
  const events = ((p.trigger && p.trigger.events) || []).filter((e) => PUBLISH.gates.dangerousTriggers.includes(e.event));
  return { events, names: events.map((e) => `\`${e.event}\``).join(' and ') };
}

// Where to point for a path's trigger: a banned event first, then the first
// event, then the publish line when no trigger is visible at all.
function triggerAnchor(p) {
  const ev = dangerousTriggers(p).events[0] || (p.trigger && p.trigger.events[0]);
  return ev ? { file: p.trigger.file, line: ev.line } : { file: p.file, line: p.line };
}

module.exports = {
  GATE, readTriggers, describeEvent, eventGate, classifyGate,
  gitlabGate, circleciApproval, dangerousTriggers, triggerAnchor,
  REQUIRE_GATE_VALUES, GATE_RANK, REQUIRE_GATE_BAR,
};
