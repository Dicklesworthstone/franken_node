const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0065-');
try {
  const oldDir = path.join(dir, 'before');
  const newDir = path.join(dir, 'after');
  fs.mkdirSync(oldDir);
  fs.writeFileSync(path.join(oldDir, 'nested.txt'), 'moved-tree');
  fs.renameSync(oldDir, newDir);
  console.log(fs.existsSync(oldDir));
  console.log(fs.existsSync(newDir));
  console.log(fs.readFileSync(path.join(newDir, 'nested.txt'), 'utf8'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
