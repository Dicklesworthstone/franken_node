const fs = require('fs');
fs.writeFileSync('bytes.bin', Buffer.from([0, 1, 127, 128, 255]));
const buf = fs.readFileSync('bytes.bin');
console.log(buf.length);
console.log(Array.from(buf).join(','));
