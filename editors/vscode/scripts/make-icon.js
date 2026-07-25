#!/usr/bin/env node
'use strict';
// Dependency-free icon generator (zlib only): renders a 128×128 PNG — a white
// magnifying lens on a red rounded square, matching the Action's search/red
// branding. Rendered at 3× and box-downsampled for anti-aliasing.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const N = 128, S = 3, W = N * S; // supersampled canvas
const RED = [0xE1, 0x1D, 0x2B];
const WHITE = [0xFF, 0xFF, 0xFF];

const cx = 0.44 * W, cy = 0.44 * W;
const ringOuter = 0.29 * W, ringInner = ringOuter - 0.095 * W;
const cornerR = 0.16 * W;
const hs = [cx + Math.SQRT1_2 * ringOuter, cy + Math.SQRT1_2 * ringOuter]; // handle start (on ring)
const he = [0.82 * W, 0.82 * W]; // handle end
const handleHalf = 0.052 * W;

function inRoundRect(x, y) {
  const qx = Math.abs(x - W / 2) - (W / 2 - cornerR);
  const qy = Math.abs(y - W / 2) - (W / 2 - cornerR);
  const ax = Math.max(qx, 0), ay = Math.max(qy, 0);
  return Math.hypot(ax, ay) - cornerR <= 0;
}
function distToSeg(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
// hard-edged colour at a supersample point → [r,g,b,a]
function sample(x, y) {
  if (!inRoundRect(x, y)) return [0, 0, 0, 0];
  const d = Math.hypot(x - cx, y - cy);
  const inRing = d >= ringInner && d <= ringOuter;
  const inHandle = distToSeg(x, y, hs[0], hs[1], he[0], he[1]) <= handleHalf;
  const c = inRing || inHandle ? WHITE : RED;
  return [c[0], c[1], c[2], 255];
}

// render + premultiplied box-downsample to N×N
const px = Buffer.alloc(N * N * 4);
for (let y = 0; y < N; y++) {
  for (let x = 0; x < N; x++) {
    let sr = 0, sg = 0, sb = 0, sa = 0;
    for (let sy = 0; sy < S; sy++) {
      for (let sx = 0; sx < S; sx++) {
        const [r, g, b, a] = sample(x * S + sx + 0.5, y * S + sy + 0.5);
        sr += r * a; sg += g * a; sb += b * a; sa += a;
      }
    }
    const o = (y * N + x) * 4;
    const a = Math.round(sa / (S * S));
    px[o] = sa ? Math.round(sr / sa) : 0;
    px[o + 1] = sa ? Math.round(sg / sa) : 0;
    px[o + 2] = sa ? Math.round(sb / sa) : 0;
    px[o + 3] = a;
  }
}

// PNG encode (RGBA, filter 0)
const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
const crc32 = (buf) => {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
};
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(N, 0); ihdr.writeUInt32BE(N, 4); ihdr[8] = 8; ihdr[9] = 6;
const raw = Buffer.alloc(N * (1 + N * 4));
for (let y = 0; y < N; y++) { raw[y * (1 + N * 4)] = 0; px.copy(raw, y * (1 + N * 4) + 1, y * N * 4, (y + 1) * N * 4); }
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);
const out = path.join(__dirname, '..', 'icon.png');
fs.writeFileSync(out, png);
console.log(`wrote ${out} (${png.length} bytes)`);
