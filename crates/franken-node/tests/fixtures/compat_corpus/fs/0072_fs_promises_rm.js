const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0072-');
(async () => {
  try {
    const nested = path.join(dir, 'a', 'b');
    await fs.promises.mkdir(nested, { recursive: true });
    await fs.promises.writeFile(path.join(nested, 'leaf.txt'), 'bye');
    await fs.promises.rm(path.join(dir, 'a'), { recursive: true });
    await fs.promises.rm(path.join(dir, 'never-existed'), { force: true });
    console.log(fs.existsSync(path.join(dir, 'a')));
    console.log('rm-ok');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
