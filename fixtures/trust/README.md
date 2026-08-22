# trust fixtures

Packuments captured from `registry.npmjs.org` on 2026-08-22 by
`node scripts/capture-trust-fixtures.js`, trimmed to the fields the
trust-downgrade check reads: `time`, and per version `dist.tarball`,
`dist.attestations`, `_npmUser` (name plus the `trustedPublisher` stamp).
Everything in these four files is real registry data:

- `axios-packument.json`: attested since 1.6.1. Its real history contains
  genuine downgrades, the 0.29/0.30 maintenance line and 1.13.3 (published
  2026-01-25 with no attestations, after 1.13.2 carried provenance).
- `commander-packument.json`: no version ever attested, the no-finding case.
- `ms-packument.json`: adopted attestations mid-history and kept them.
- `sigstore-packument.json`: consistently attested, trusted publisher from
  4.0.0.

`axios-downgrade-reconstructed.json` is **partly reconstructed** and labelled
so. The malicious axios 1.14.1 (published 2026-03-31 from a stolen maintainer
account, without attestations, live under three hours) was unpublished, so
`GET /axios/1.14.1` returns 404 today and the attacking version cannot be
captured. This fixture holds the real axios entries up to 1.13.2 plus a
version doc for 1.14.1 with no attestations under its **real** publish
timestamp, which the live packument still carries in `time` even though the
version doc is gone. It reconstructs the registry state the trust-policy
proposal (npm/cli#9242) was written against; it is not a captured response.
