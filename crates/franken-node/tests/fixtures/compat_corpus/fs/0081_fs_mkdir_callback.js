const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0081-');
const nested = path.join(dir, 'x', 'y', 'z');
fs.mkdir(nested, { recursive: true }, (err) => {
  try {
    console.log(err === null);
    console.log(fs.statSync(nested).isDirectory());
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
