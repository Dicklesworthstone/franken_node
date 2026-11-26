const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0069-');
(async () => {
  try {
    const src = path.join(dir, 'src.txt');
    const dst = path.join(dir, 'dst.txt');
    await fs.promises.writeFile(src, 'copied-async');
    await fs.promises.copyFile(src, dst);
    let exclCode = 'no-throw';
    try {
      await fs.promises.copyFile(src, dst, fs.constants.COPYFILE_EXCL);
    } catch (e) {
      exclCode = e.code;
    }
    console.log(await fs.promises.readFile(dst, 'utf8'));
    console.log(exclCode);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
