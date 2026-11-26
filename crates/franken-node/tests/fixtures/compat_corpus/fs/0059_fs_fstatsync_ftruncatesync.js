const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0059-');
try {
  const file = path.join(dir, 'fd-trunc.txt');
  const fd = fs.openSync(file, 'w+');
  fs.writeSync(fd, 'abcdefghij');
  const before = fs.fstatSync(fd);
  fs.ftruncateSync(fd, 4);
  const after = fs.fstatSync(fd);
  fs.closeSync(fd);
  console.log(before.isFile(), before.size, after.size);
  console.log(fs.readFileSync(file, 'utf8'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
