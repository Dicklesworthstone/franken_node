const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0064-');
try {
  const sub = path.join(dir, 'subdir');
  fs.mkdirSync(sub);
  const st = fs.statSync(sub);
  console.log(st.isDirectory(), st.isFile(), st.isSymbolicLink());
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
