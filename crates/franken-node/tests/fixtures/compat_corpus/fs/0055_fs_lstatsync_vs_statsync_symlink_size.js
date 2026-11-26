const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0055-');
try {
  const target = path.join(dir, 'target.txt');
  const link = path.join(dir, 'sym');
  fs.writeFileSync(target, '0123456789abcdef');
  fs.symlinkSync('target.txt', link);
  const lst = fs.lstatSync(link);
  const st = fs.statSync(link);
  console.log(lst.isSymbolicLink(), lst.isFile(), lst.isDirectory());
  console.log(st.isSymbolicLink(), st.isFile(), st.isDirectory(), st.size);
  console.log(fs.readlinkSync(link));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
