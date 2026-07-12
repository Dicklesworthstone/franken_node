const fs = require('fs');
const fd = fs.openSync('sync.txt', 'w');
fs.writeSync(fd, 'durable');
fs.fsyncSync(fd);
fs.closeSync(fd);
console.log(fs.readFileSync('sync.txt', 'utf8'));
