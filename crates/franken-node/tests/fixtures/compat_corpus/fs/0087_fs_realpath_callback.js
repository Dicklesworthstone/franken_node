const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0087-');
const sub = path.join(dir, 'inner');
fs.mkdirSync(sub);
const target = path.join(dir, 'base.txt');
fs.writeFileSync(target, 'here');
const dotted = path.join(sub, '..', 'base.txt');
fs.realpath(dotted, (err, resolved) => {
  try {
    console.log(err === null);
    console.log(path.isAbsolute(resolved));
    console.log(path.basename(resolved));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
