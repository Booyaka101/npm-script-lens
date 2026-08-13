'use strict';
// The npm CONTRACT, every assumption this tool makes about npm's own
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
// this: do not inline the number 12 anywhere else.
const MIN_ALLOWSCRIPTS_NPM = 12;

// The package.json field that holds the allowlist, and the value semantics.
// A decision is any key present (bare name OR name@version), true = allow,
// false = deny; both count as "reviewed".
const ALLOWSCRIPTS_FIELD = 'allowScripts';

// The argv we hand npm to enumerate pending script approvals, and the JSON
// keys we read back from it. These are the MOST fragile coupling, an
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

// npm v12's OTHER two flipped defaults: git and remote-URL dependency
// resolution. Both keys are strict enums, `allow-git=true` / a bare
// `--allow-git` is INVALID, which several published migration guides get
// wrong. `root` allows only deps declared in the project's root package.json;
// any transitive git/remote dep forces `all`. Verified against
// npm/cli workspaces/config definitions.js (type ['all','none','root'],
// default 'none') and the 2026-06-09 v12 breaking-changes changelog.
const SOURCES = {
  git: { key: 'allow-git', introduced: '11.10.0' },
  remote: { key: 'allow-remote', introduced: '11.15.0' },
  values: ['all', 'none', 'root'],
  default: 'none',
  // the npm major where 'none' becomes the enforced default (before that the
  // keys exist behind warnings, 11.16.0+ warns, v12 blocks)
  enforcedInNpm: 12,
};

// The two npm-v12 approve-scripts tooling bugs we detect, with their live
// upstream status. Findings and reports pull ref/status from here so they
// self-document how current they are, the antidote to a detector quietly
// outliving the bug it was written for. `fixedInNpm` stays null until a
// maintainer confirms the exact npm version carrying the fix; doctor and the
// gaps report surface that so nobody trusts a stale detector.
const DETECTORS = {
  optionalGap: {
    id: 'v12-optional-gap',
    issue: 'https://github.com/npm/cli/issues/9562',
    upstream: 'closed via npm/cli PR #9597 (merged 2026-06-23), backported as #9602',
    // PR #9597 made collectUnreviewedScripts skip INERT nodes so the strict
    // check matches what actually installs. Shipped in npm 11.18.0 via the
    // release/v11 backport, and carried forward into npm 12.0.0 (2026-07-08).
    fixedInNpm: '11.18.0',
    note: 'npm 12.0.0+ also carries this fix (the v11 backport landed before the v12 cut)',
  },
  eglobal: {
    id: 'v12-eglobal-risk',
    issue: 'https://github.com/npm/cli/issues/9463',
    upstream: 'suggestion added upstream (npm/cli commit c14e87c)',
    fixedInNpm: null,
  },
  // allow-git=root wrongly rejected ROOT-level git deps in npm 11.12.1
  // ("Fetching non-root packages of type git have been disabled"), so any
  // `root` recommendation must be version-gated until the fixed npm version
  // is pinned here.
  allowGitRoot: {
    id: 'v12-allow-git-root',
    issue: 'https://github.com/npm/cli/issues/9189',
    upstream: 'closed via npm/cli PR #9206',
    fixedInNpm: null,
  },
};

// The publish-side contract: npm's bypass-2FA granular access tokens lose
// DIRECT PUBLISH around January 2027. Verified verbatim against the GitHub
// changelog of 2026-07-31 ("restricting npm bypass-2FA granular access
// tokens"): "2FA-bypass tokens will also lose direct publish. Their publishing
// surface will reduce to reading private packages and staging a publish, which
// a maintainer approves with 2FA. We are targeting January 2027 for this
// update." The two sanctioned replacements each carry version floors, quoted
// verbatim from docs.npmjs.com, every message naming a date, floor, command
// or provider reads it from here.
const PUBLISH = {
  cliff: {
    date: 'January 2027',
    quote: '2FA-bypass tokens will also lose direct publish. Their publishing surface '
      + 'will reduce to reading private packages and staging a publish, which a '
      + 'maintainer approves with 2FA. We are targeting January 2027 for this update.',
    changelog: 'https://github.blog/changelog/2026-07-31-restricting-npm-bypass-2fa-granular-access-tokens/',
  },
  trusted: {
    // "Trusted publishing requires npm CLI version 11.5.1 or later and Node
    // version 22.14.0 or higher."
    minNpm: '11.5.1',
    minNode: '22.14.0',
    docs: 'https://docs.npmjs.com/trusted-publishers',
    // The docs support ONLY these three; verbatim: "Self-hosted runners are
    // not currently supported but are planned for future releases."
    providers: ['GitHub Actions (GitHub-hosted runners)', 'GitLab.com (shared runners)', 'CircleCI (cloud)'],
    selfHostedQuote: 'Self-hosted runners are not currently supported but are planned for future releases.',
    gitlabAudience: 'npm:registry.npmjs.org',
    circleciTokenVar: 'NPM_ID_TOKEN',
  },
  staged: {
    // "Staged publishing requires npm CLI version 11.15.0 or later and Node
    // version 22.14.0 or higher."
    minNpm: '11.15.0',
    minNode: '22.14.0',
    docs: 'https://docs.npmjs.com/staged-publishing',
    commands: {
      publish: 'npm stage publish',
      list: 'npm stage list',
      view: 'npm stage view <stage-id>',
      download: 'npm stage download <stage-id>',
      approve: 'npm stage approve <stage-id>',
    },
  },
  // setup-node up to v6 answers `registry-url:` by writing authLine into an
  // .npmrc and exporting the dummy token, which makes npm skip the OIDC
  // exchange. Fixed in v7.0.0; the trusted-publishers docs still show v6.
  oidc: {
    setupNodeFixedIn: '7.0.0',
    dummyToken: 'XXXXX-XXXXX-XXXXX-XXXXX',
    authLine: '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}',
    hosts: ['registry.npmjs.org'],
    issues: [
      'https://github.com/npm/documentation/issues/1960',
      'https://github.com/actions/setup-node/issues/1551',
    ],
    fixRelease: 'https://github.com/actions/setup-node/releases/tag/v7.0.0',
    quote: "npm CLI sees the `_authToken=` line as 'auth is configured' and does NOT "
      + 'initiate the OIDC token exchange, instead attempting a classic publish with '
      + 'empty credentials',
  },
};

// The npm versions from which `--strict-allow-scripts` skips INERT optional
// dependencies (a dep whose os/cpu excludes the current platform, which reify
// removes before install scripts run). Two lines because the fix reached the
// v11 and v12 release lines at different versions, and "12.0.0 > 11.18.0" is
// not a comparison that answers "does THIS npm have it" for an npm 11.x user.
const INERT_SKIP_FROM = { npm11: '11.18.0', npm12: '12.0.0' };

// Does this npm full version ("11.17.0") skip inert optional deps in the
// strict check? null/unparseable ⇒ false (fail loud, keep warning).
function skipsInertOptional(fullVersion) {
  if (typeof fullVersion !== 'string') return false;
  const m = fullVersion.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const [major, minor, patch] = m.slice(1).map(Number);
  const floor = major >= 12 ? INERT_SKIP_FROM.npm12 : INERT_SKIP_FROM.npm11;
  const [fMajor, fMinor, fPatch] = floor.split('.').map(Number);
  if (major !== fMajor) return major > fMajor;
  if (minor !== fMinor) return minor > fMinor;
  return patch >= fPatch;
}

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
  SOURCES,
  PUBLISH,
  DETECTORS,
  INERT_SKIP_FROM,
  skipsInertOptional,
  enforcesAllowScripts,
};
