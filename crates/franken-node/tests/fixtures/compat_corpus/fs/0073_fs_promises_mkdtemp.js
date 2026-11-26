const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0073-');
(async () => {
  try {
    const prefix = path.join(dir, 'ptmp-');
    const created = await fs.promises.mkdtemp(prefix);
    const child = path.join(created, 'inside.txt');
    await fs.promises.writeFile(child, 'ok');
    console.log(created.startsWith(prefix));
    console.log((await fs.promises.stat(created)).isDirectory());
    console.log(await fs.promises.readFile(child, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
