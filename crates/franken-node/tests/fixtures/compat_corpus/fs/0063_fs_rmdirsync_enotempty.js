const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0063-');
try {
  const sub = path.join(dir, 'nonempty');
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(sub, 'child.txt'), 'stay');
  let code = 'no-throw';
  try {
    fs.rmdirSync(sub);
  } catch (e) {
    code = e.code;
  }
  console.log(code);
  console.log(fs.existsSync(path.join(sub, 'child.txt')));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
