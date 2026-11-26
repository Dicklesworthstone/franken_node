const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0068-');
(async () => {
  try {
    const file = path.join(dir, 'log.txt');
    await fs.promises.appendFile(file, 'line1\n');
    await fs.promises.appendFile(file, 'line2\n');
    await fs.promises.appendFile(file, 'line3');
    console.log(await fs.promises.readFile(file, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
