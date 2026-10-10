// Generates icons/icon{16,32,48,128}.png: a blue shield with a white check mark.
// No dependencies: writes the PNG bytes by hand with zlib.
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function insideShield(x, y) {
  if (y < 0.08 || y > 0.94) return false;
  const halfWidth = y < 0.5 ? 0.4 : 0.4 * Math.sqrt(Math.max(0, 1 - ((y - 0.5) / 0.44) ** 2));
  return Math.abs(x - 0.5) <= halfWidth;
}

function distToSegment(px, py, ax, ay, bx, by) {
  const t = Math.max(0, Math.min(1, ((px - ax) * (bx - ax) + (py - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2)));
  return Math.hypot(px - (ax + t * (bx - ax)), py - (ay + t * (by - ay)));
}

function onCheck(x, y) {
  const d = Math.min(distToSegment(x, y, 0.3, 0.5, 0.45, 0.65), distToSegment(x, y, 0.45, 0.65, 0.72, 0.35));
  return d < 0.065;
}

function render(size) {
  const SS = 4; // supersampling for smooth edges
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let py = 0; py < size; py++) {
    raw[py * (size * 4 + 1)] = 0; // filter: none
    for (let px = 0; px < size; px++) {
      let shield = 0;
      let check = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const x = (px + (sx + 0.5) / SS) / size;
          const y = (py + (sy + 0.5) / SS) / size;
          if (insideShield(x, y)) {
            shield++;
            if (onCheck(x, y)) check++;
          }
        }
      }
      const n = SS * SS;
      const mix = check / Math.max(shield, 1);
      const o = py * (size * 4 + 1) + 1 + px * 4;
      raw[o] = Math.round(26 + (255 - 26) * mix);
      raw[o + 1] = Math.round(115 + (255 - 115) * mix);
      raw[o + 2] = Math.round(232 + (255 - 232) * mix);
      raw[o + 3] = Math.round((255 * shield) / n);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const outDir = path.join(__dirname, "..", "icons");
fs.mkdirSync(outDir, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  fs.writeFileSync(path.join(outDir, `icon${size}.png`), render(size));
  console.log(`icons/icon${size}.png`);
}
