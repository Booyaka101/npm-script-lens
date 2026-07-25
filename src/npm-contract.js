'use strict';
// The npm CONTRACT — every assumption this tool makes about npm's own
// behavior, in one place. npm-script-lens is only useful as long as it tracks
// npm; when npm shifts, this is the file to patch, and `npm-script-lens
// doctor` is the probe that tells you it shifted. Nothing outside this module
// should hard-code an npm key name, flag, command, or version threshold.
//
// Verified against the npm v12 breaking-changes changelog
// (github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12) and
// real npm 12.0.1 (see LESSONS.md / PROGRESS.md for the empirical quirks).

// npm major at which install scripts became opt-in and the allowScripts
// allowlist began to be enforced. Every "is this npm affected?" gate reads
// this — do not inline the number 12 anywhere else.
const MIN_ALLOWSCRIPTS_NPM = 12;

// The package.json field that holds the allowlist, and the value semantics.
// A decision is any key present (bare name OR name@version), true = allow,
// false = deny; both count as "reviewed".
const ALLOWSCRIPTS_FIELD = 'allowScripts';

// The argv we hand npm to enumerate pending script approvals, and the JSON
// keys we read back from it. These are the MOST fragile coupling — an
// undocumented internal shape. doctor self-tests the parser against the
// canonical samples below so drift here surfaces loudly.
const DRY_RUN_ARGS = ['install', '--dry-run', '--json'];
const UNREVIEWED_KEY = 'unreviewedScripts';
// keys that mark a *successful* install summary (used to tell "nothing
// pending" from "npm errored" when UNREVIEWED_KEY is absent).
const SUMMARY_KEYS = ['added', 'audited', 'removed', 'changed'];

// npm's user-facing surface, referenced in our human/fix text. Kept here so a
// rename in npm is a one-line edit, not a grep-and-pray across messages.
const NPM_CMD = {
  approveScripts: 'npm approve-scripts',
  denyScripts: 'npm deny-scripts',
  allowScriptsPending: 'npm approve-scripts --allow-scripts-pending',
  strictAllowScripts: 'npm ci --strict-allow-scripts',
  allowScriptsFlag: '--allow-scripts',
  ignoreScriptsFlag: '--ignore-scripts',
};

// Canonical dry-run outputs, used by doctor as a parser self-test: if npm's
// real output stops matching these shapes, the live probe reports UNRECOGNIZED.
const SAMPLE_DRY_RUN = {
  // human "add pkg x.y.z" lines precede the JSON on stdout (real npm 12.0.1)
  pending: 'add sharp 0.33.5\n' + JSON.stringify({
    added: 1,
    [UNREVIEWED_KEY]: [{ name: 'sharp', version: '0.33.5', path: 'x', scripts: { install: 'node install/check' } }],
  }),
  // everything covered ⇒ npm OMITS the key entirely (must read as "empty")
  empty: 'add sharp 0.33.5\n' + JSON.stringify({ added: 1, audited: 0, removed: 0 }),
};

// The two npm-v12 approve-scripts tooling bugs we detect, with their live
// upstream status. Findings and reports pull ref/status from here so they
// self-document how current they are — the antidote to a detector quietly
// outliving the bug it was written for. `fixedInNpm` stays null until a
// maintainer confirms the exact npm version carrying the fix; doctor and the
// gaps report surface that so nobody trusts a stale detector.
const DETECTORS = {
  optionalGap: {
    id: 'v12-optional-gap',
    issue: 'https://github.com/npm/cli/issues/9562',
    upstream: 'closed via npm/cli PR #9597',
    fixedInNpm: null,
  },
  eglobal: {
    id: 'v12-eglobal-risk',
    issue: 'https://github.com/npm/cli/issues/9463',
    upstream: 'suggestion added upstream (npm/cli commit c14e87c)',
    fixedInNpm: null,
  },
};

// npm >= MIN is where allowScripts is enforced.
const enforcesAllowScripts = (major) => typeof major === 'number' && major >= MIN_ALLOWSCRIPTS_NPM;

module.exports = {
  MIN_ALLOWSCRIPTS_NPM,
  ALLOWSCRIPTS_FIELD,
  DRY_RUN_ARGS,
  UNREVIEWED_KEY,
  SUMMARY_KEYS,
  NPM_CMD,
  SAMPLE_DRY_RUN,
  DETECTORS,
  enforcesAllowScripts,
};
