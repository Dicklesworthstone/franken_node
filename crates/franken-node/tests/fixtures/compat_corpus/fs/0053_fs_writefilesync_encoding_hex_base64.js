const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0053-');
try {
  const hexFile = path.join(dir, 'from-hex.txt');
  const b64File = path.join(dir, 'from-b64.txt');
  fs.writeFileSync(hexFile, '6672616e6b656e', { encoding: 'hex' });
  fs.writeFileSync(b64File, 'bm9kZS1jb21wYXQ=', { encoding: 'base64' });
  console.log(fs.readFileSync(hexFile, 'utf8'));
  console.log(fs.readFileSync(b64File, 'utf8'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
