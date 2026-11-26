const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0083-');
const src = path.join(dir, 'old.txt');
const dst = path.join(dir, 'new.txt');
fs.writeFileSync(src, 'moved-cb');
fs.rename(src, dst, (err) => {
  try {
    console.log(err === null, fs.existsSync(src), fs.existsSync(dst));
    console.log(fs.readFileSync(dst, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
