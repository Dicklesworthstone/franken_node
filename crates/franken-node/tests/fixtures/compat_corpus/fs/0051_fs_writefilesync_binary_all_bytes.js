const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0051-');
try {
  const file = path.join(dir, 'all-bytes.bin');
  const expected = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) expected[i] = i;
  fs.writeFileSync(file, expected);
  const actual = fs.readFileSync(file);
  console.log(Buffer.isBuffer(actual));
  console.log(actual.length);
  console.log(actual.equals(expected));
  console.log(actual[0], actual[127], actual[128], actual[255]);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
