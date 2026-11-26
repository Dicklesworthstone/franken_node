const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0088-');
const file = path.join(dir, 'append.txt');
fs.writeFileSync(file, 'HEADER:');
const ws = fs.createWriteStream(file, { flags: 'a' });
ws.write('chunk1|');
ws.write('chunk2|');
ws.end('chunk3');
ws.on('finish', () => {
  try {
    console.log(fs.readFileSync(file, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
