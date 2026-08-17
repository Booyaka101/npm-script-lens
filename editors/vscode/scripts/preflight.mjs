#!/usr/bin/env node
/**
 * Publish preflight.
 *
 * `vsce publish` prints "DONE Published <publisher>.<name>" and exits 0 even when
 * the publisher is not fully set up, and the extension then never reaches the
 * gallery. That happened on the first 1.3.0 attempt: DONE, exit 0, and nothing
 * listed anywhere afterwards. So verify the preconditions here, against the public
 * gallery API, before handing a token to vsce.
 *
 * Usage: node scripts/preflight.mjs        (exits non-zero if not safe to publish)
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dir = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(path.join(dir, '..', 'package.json'), 'utf8'));
const { publisher, name, version } = pkg;

const fail = (msg, fix) => {
  console.error(`preflight: ${msg}`);
  if (fix) console.error(`           ${fix}`);
  process.exit(1);
};

if (!publisher) fail('package.json has no "publisher"');
if (!name) fail('package.json has no "name"');

// 1. The publisher must exist publicly. vsce will happily publish "into" a
//    publisher page that is not ready and report success.
const pubRes = await fetch(`https://marketplace.visualstudio.com/publishers/${publisher}`, {
  redirect: 'follow',
});
if (!pubRes.ok) {
  fail(
    `publisher "${publisher}" does not resolve (HTTP ${pubRes.status})`,
    `create it at https://marketplace.visualstudio.com/manage. The id must match package.json exactly`,
  );
}
console.log(`preflight: publisher "${publisher}" exists`);

// 2. Report what the gallery currently knows, so a re-publish is an informed one.
const query = await fetch('https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json;api-version=3.0-preview.1',
  },
  body: JSON.stringify({
    filters: [{ criteria: [{ filterType: 7, value: `${publisher}.${name}` }] }],
    flags: 914,
  }),
});
const found = (await query.json())?.results?.[0]?.extensions ?? [];

if (found.length === 0) {
  console.log(`preflight: ${publisher}.${name} is not in the gallery yet, this will be a first publish`);
} else {
  console.log(`preflight: gallery has ${publisher}.${name} v${found[0].versions?.[0]?.version}`);
}
console.log(`preflight: about to publish v${version}, OK`);
