const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0089-');
const file = path.join(dir, 'range.txt');
fs.writeFileSync(file, '0123456789abcdefghij');
const rs = fs.createReadStream(file, {
  start: 4,
  end: 13,
  encoding: 'utf8',
  highWaterMark: 4,
});
const chunks = [];
rs.on('data', (chunk) => chunks.push(chunk));
rs.on('end', () => {
  try {
    console.log(chunks.join('|'));
    console.log(chunks.join('').length);
    console.log(chunks.every((c) => c.length <= 4));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
