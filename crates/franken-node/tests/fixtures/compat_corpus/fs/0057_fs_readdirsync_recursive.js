const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0057-');
try {
  fs.mkdirSync(path.join(dir, 'alpha', 'beta'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'root.txt'), 'r');
  fs.writeFileSync(path.join(dir, 'alpha', 'mid.txt'), 'm');
  fs.writeFileSync(path.join(dir, 'alpha', 'beta', 'leaf.txt'), 'l');
  const entries = fs.readdirSync(dir, { recursive: true })
    .map((p) => p.replace(/\\/g, '/'))
    .sort();
  console.log(entries.join(','));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
