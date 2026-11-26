const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0090-');
const rs = fs.createReadStream(path.join(dir, 'does-not-exist.txt'));
rs.on('error', (err) => {
  try {
    console.log(err instanceof Error);
    console.log(err.code);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
