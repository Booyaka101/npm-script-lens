'use strict';
// Regenerates fixtures/trust/*.json from the live registry. Each fixture is a
// real packument trimmed to the fields the downgrade check reads (version,
// time, dist.attestations, _npmUser.trustedPublisher); the axios downgrade
// fixture additionally RECONSTRUCTS the unpublished malicious 1.14.1 entry,
// see fixtures/trust/README.md for exactly what is real and what is not.
const fs = require('node:fs');
const path = require('node:path');

const OUT = path.join(__dirname, '..', 'fixtures', 'trust');

function trimVersion(doc) {
  const out = { name: doc.name, version: doc.version, dist: { tarball: doc.dist.tarball } };
  if (doc.dist.attestations) out.dist.attestations = doc.dist.attestations;
  if (doc._npmUser) {
    out._npmUser = { name: doc._npmUser.name };
    if (doc._npmUser.trustedPublisher) out._npmUser.trustedPublisher = doc._npmUser.trustedPublisher;
  }
  return out;
}

function trimPackument(p, keepVersion) {
  const versions = {};
  const time = { created: p.time.created, modified: p.time.modified };
  for (const v of Object.keys(p.versions)) {
    if (!keepVersion(v)) continue;
    versions[v] = trimVersion(p.versions[v]);
    time[v] = p.time[v];
  }
  // time entries for UNPUBLISHED versions survive in the live packument (axios
  // 1.14.1 has a time entry and no versions entry); keep them so the fixture
  // preserves that shape for the unpublished-gap tests.
  for (const v of Object.keys(p.time)) {
    if (!(v in time) && keepVersion(v)) time[v] = p.time[v];
  }
  return { name: p.name, 'dist-tags': p['dist-tags'], time, versions };
}

async function capture(name, file, keepVersion = () => true) {
  const res = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2f')}`);
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${name}`);
  const doc = trimPackument(await res.json(), keepVersion);
  fs.writeFileSync(path.join(OUT, file), `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`${file}: ${Object.keys(doc.versions).length} versions (captured ${new Date().toISOString().slice(0, 10)})`);
  return doc;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  // attested since 1.6.1; its REAL history holds genuine downgrades (the 0.x
  // maintenance line, and 1.13.3 published 2026-01-25 without attestations)
  const axios = await capture('axios', 'axios-packument.json');
  // never attested at any version, the no-finding case
  await capture('commander', 'commander-packument.json');
  // adopted attestations mid-history and kept them, a ratchet-up, no finding
  await capture('ms', 'ms-packument.json');
  // consistently attested with a trusted-publisher tail from 4.0.0
  await capture('sigstore', 'sigstore-packument.json');

  // The downgrade case. axios 1.14.1 (published 2026-03-31 from a stolen
  // maintainer account, without attestations) was unpublished, so it cannot be
  // captured live. Reconstruct it: real entries up to 1.13.2, plus a version
  // doc for 1.14.1 with no attestations under its REAL publish timestamp,
  // which the live packument still carries in `time`.
  const cut = Date.parse(axios.time['1.13.2']);
  const down = {
    name: 'axios',
    'dist-tags': { latest: '1.14.1' },
    time: { created: axios.time.created, modified: axios.time.modified },
    versions: {},
  };
  for (const [v, doc] of Object.entries(axios.versions)) {
    if (Date.parse(axios.time[v]) > cut) continue;
    down.versions[v] = doc;
    down.time[v] = axios.time[v];
  }
  down.time['1.14.1'] = axios.time['1.14.1'];
  down.versions['1.14.1'] = {
    name: 'axios',
    version: '1.14.1',
    dist: { tarball: 'https://registry.npmjs.org/axios/-/axios-1.14.1.tgz' },
    _npmUser: { name: 'jasonsaayman' },
  };
  fs.writeFileSync(path.join(OUT, 'axios-downgrade-reconstructed.json'), `${JSON.stringify(down, null, 2)}\n`);
  console.log(`axios-downgrade-reconstructed.json: ${Object.keys(down.versions).length} versions (1.14.1 reconstructed)`);
})().catch((err) => { console.error(err.message); process.exit(1); });
