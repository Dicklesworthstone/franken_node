const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0067-');
(async () => {
  try {
    const file = path.join(dir, 'f.txt');
    const sub = path.join(dir, 'd');
    const link = path.join(dir, 'l');
    await fs.promises.writeFile(file, 'hello');
    await fs.promises.mkdir(sub);
    await fs.promises.symlink('f.txt', link);
    const stFile = await fs.promises.stat(file);
    const stDir = await fs.promises.stat(sub);
    const lstLink = await fs.promises.lstat(link);
    const stLink = await fs.promises.stat(link);
    const target = await fs.promises.readlink(link);
    console.log(stFile.isFile(), stFile.size);
    console.log(stDir.isDirectory(), stDir.isFile());
    console.log(lstLink.isSymbolicLink(), stLink.isFile(), target);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
