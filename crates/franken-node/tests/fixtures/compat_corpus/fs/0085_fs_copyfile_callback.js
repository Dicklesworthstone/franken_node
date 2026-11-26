const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0085-');
const src = path.join(dir, 'src.txt');
const dst = path.join(dir, 'dst.txt');
fs.writeFileSync(src, 'async-copy-bytes');
fs.copyFile(src, dst, (err) => {
  try {
    console.log(err === null);
    console.log(fs.readFileSync(src, 'utf8'));
    console.log(fs.readFileSync(dst, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
