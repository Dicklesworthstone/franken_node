const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0056-');
try {
  fs.writeFileSync(path.join(dir, 'plain.txt'), 'abc');
  fs.mkdirSync(path.join(dir, 'folder'));
  fs.symlinkSync('plain.txt', path.join(dir, 'alias'));
  const entries = fs.readdirSync(dir, { withFileTypes: true })
    .map((d) => `${d.name}:f=${d.isFile()},d=${d.isDirectory()},s=${d.isSymbolicLink()}`)
    .sort();
  console.log(entries.join('|'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
