const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0066-');
try {
  const file = path.join(dir, 'grow.bin');
  fs.writeFileSync(file, Buffer.from([0x41, 0x42]));
  fs.truncateSync(file, 6);
  const buf = fs.readFileSync(file);
  console.log(buf.length);
  console.log(Array.from(buf).join(','));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
