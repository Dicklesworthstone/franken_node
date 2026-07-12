const fs = require('fs');
const fd = fs.openSync('fd.txt', 'w');
const n = fs.writeSync(fd, 'fd write');
fs.closeSync(fd);
console.log(n);
console.log(fs.readFileSync('fd.txt', 'utf8'));
