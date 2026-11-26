const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0074-');
(async () => {
  try {
    const file = path.join(dir, 'check.txt');
    await fs.promises.writeFile(file, 'ok');
    await fs.promises.access(file, fs.constants.F_OK | fs.constants.R_OK | fs.constants.W_OK);
    let missingCode = 'no-throw';
    try {
      await fs.promises.access(path.join(dir, 'missing.txt'), fs.constants.F_OK);
    } catch (e) {
      missingCode = e.code;
    }
    console.log('accessible');
    console.log(missingCode);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
