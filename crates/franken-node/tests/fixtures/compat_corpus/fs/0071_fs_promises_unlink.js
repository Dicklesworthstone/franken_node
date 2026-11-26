const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0071-');
(async () => {
  try {
    const file = path.join(dir, 'gone.txt');
    await fs.promises.writeFile(file, 'temp');
    await fs.promises.unlink(file);
    let code = 'no-throw';
    try {
      await fs.promises.unlink(file);
    } catch (e) {
      code = e.code;
    }
    console.log(fs.existsSync(file));
    console.log(code);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
