const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0082-');
const file = path.join(dir, 'del.txt');
fs.writeFileSync(file, 'bye');
fs.unlink(file, (err) => {
  try {
    console.log(err === null);
    console.log(fs.existsSync(file));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
