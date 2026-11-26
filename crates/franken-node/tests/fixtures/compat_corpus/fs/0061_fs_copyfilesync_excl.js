const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0061-');
try {
  const src = path.join(dir, 'src.txt');
  const dst = path.join(dir, 'dst.txt');
  fs.writeFileSync(src, 'new-data');
  fs.writeFileSync(dst, 'keep-me');
  let code = 'no-throw';
  try {
    fs.copyFileSync(src, dst, fs.constants.COPYFILE_EXCL);
  } catch (e) {
    code = e.code;
  }
  console.log(code);
  console.log(fs.readFileSync(dst, 'utf8'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
