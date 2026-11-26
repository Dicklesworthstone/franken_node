const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0076-');
(async () => {
  try {
    const file = path.join(dir, 'shrink.txt');
    await fs.promises.writeFile(file, '0123456789');
    await fs.promises.truncate(file, 4);
    const mid = await fs.promises.readFile(file, 'utf8');
    await fs.promises.truncate(file);
    const empty = await fs.promises.readFile(file, 'utf8');
    console.log(mid, mid.length);
    console.log(empty.length);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
