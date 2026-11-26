const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0060-');
try {
  const src = path.join(dir, 'src.txt');
  const dst = path.join(dir, 'dst.txt');
  fs.writeFileSync(src, 'fresh-content');
  fs.writeFileSync(dst, 'stale-longer-previous-content');
  fs.copyFileSync(src, dst);
  console.log(fs.readFileSync(dst, 'utf8'));
  console.log(fs.readFileSync(src, 'utf8'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
