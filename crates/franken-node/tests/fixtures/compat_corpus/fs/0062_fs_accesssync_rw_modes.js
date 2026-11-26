const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0062-');
try {
  const file = path.join(dir, 'rw.txt');
  fs.writeFileSync(file, 'ok');
  fs.accessSync(file, fs.constants.R_OK | fs.constants.W_OK);
  console.log('rw-ok');
  let missingCode = 'no-throw';
  try {
    fs.accessSync(path.join(dir, 'absent.txt'), fs.constants.F_OK);
  } catch (e) {
    missingCode = e.code;
  }
  console.log(missingCode);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
