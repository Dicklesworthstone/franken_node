const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0054-');
try {
  const file = path.join(dir, 'exclusive.txt');
  fs.writeFileSync(file, 'original', { flag: 'wx' });
  let code = 'no-throw';
  try {
    fs.writeFileSync(file, 'overwrite', { flag: 'wx' });
  } catch (e) {
    code = e.code;
  }
  console.log(code);
  console.log(fs.readFileSync(file, 'utf8'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
