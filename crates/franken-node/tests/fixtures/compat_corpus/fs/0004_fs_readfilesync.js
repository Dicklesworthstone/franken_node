const fs = require('fs');
fs.writeFileSync('buf.txt', 'buffer bytes');
const buf = fs.readFileSync('buf.txt');
console.log(Buffer.isBuffer(buf));
console.log(buf.toString());
