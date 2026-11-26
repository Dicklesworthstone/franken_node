const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0086-');
const file = path.join(dir, 'perm.txt');
fs.writeFileSync(file, 'ok');
fs.access(file, fs.constants.R_OK | fs.constants.W_OK, (err1) => {
  fs.access(path.join(dir, 'missing.txt'), fs.constants.F_OK, (err2) => {
    try {
      console.log(err1 === null);
      console.log(err2 !== null, err2.code);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
