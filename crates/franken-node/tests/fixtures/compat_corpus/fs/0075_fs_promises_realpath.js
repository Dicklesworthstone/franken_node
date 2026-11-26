const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0075-');
(async () => {
  try {
    const sub = path.join(dir, 'nested');
    await fs.promises.mkdir(sub);
    const target = path.join(dir, 'real.txt');
    await fs.promises.writeFile(target, 'canonical');
    const link = path.join(dir, 'ptr');
    await fs.promises.symlink('real.txt', link);
    const resolvedTarget = await fs.promises.realpath(target);
    const resolvedLink = await fs.promises.realpath(link);
    const resolvedDotted = await fs.promises.realpath(path.join(sub, '..', 'real.txt'));
    console.log(path.isAbsolute(resolvedLink));
    console.log(resolvedLink === resolvedTarget);
    console.log(resolvedDotted === resolvedTarget);
    console.log(path.basename(resolvedLink));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
