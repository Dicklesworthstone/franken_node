const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0078-');
const prefix = path.join(dir, 'cb-');
fs.mkdtemp(prefix, (err, folder) => {
  try {
    console.log(err === null);
    console.log(folder.startsWith(prefix));
    console.log(fs.statSync(folder).isDirectory());
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
