const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0070-');
(async () => {
  try {
    const a = path.join(dir, 'a.txt');
    const b = path.join(dir, 'b.txt');
    await fs.promises.writeFile(a, 'renamed-payload');
    await fs.promises.rename(a, b);
    console.log(fs.existsSync(a), fs.existsSync(b));
    console.log(await fs.promises.readFile(b, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
