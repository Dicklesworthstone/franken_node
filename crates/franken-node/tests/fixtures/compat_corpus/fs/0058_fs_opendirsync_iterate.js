const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0058-');
try {
  fs.writeFileSync(path.join(dir, 'one.txt'), '1');
  fs.writeFileSync(path.join(dir, 'two.txt'), '2');
  fs.mkdirSync(path.join(dir, 'sub'));
  const handle = fs.opendirSync(dir);
  const seen = [];
  let entry;
  while ((entry = handle.readSync()) !== null) {
    seen.push(`${entry.name}:${entry.isFile() ? 'F' : entry.isDirectory() ? 'D' : 'O'}`);
  }
  handle.closeSync();
  console.log(seen.sort().join(','));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
