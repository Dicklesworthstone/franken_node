const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0052-');
try {
  const file = path.join(dir, 'latin1.bin');
  const raw = Buffer.from([0x00, 0x41, 0x7f, 0x80, 0xe9, 0xff]);
  fs.writeFileSync(file, raw);
  const decoded = fs.readFileSync(file, 'latin1');
  const codes = [];
  for (let i = 0; i < decoded.length; i++) codes.push(decoded.charCodeAt(i));
  console.log(typeof decoded);
  console.log(decoded.length);
  console.log(codes.join(','));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
