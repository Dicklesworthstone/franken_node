const fs = require('fs');
fs.writeFileSync('r.txt', 'abcdefgh');
const fd = fs.openSync('r.txt', 'r');
const buf = Buffer.alloc(4);
const n = fs.readSync(fd, buf, 0, 4, 2);
fs.closeSync(fd);
console.log(n);
console.log(buf.toString('utf8'));
