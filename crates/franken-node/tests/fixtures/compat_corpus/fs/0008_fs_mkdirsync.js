const fs = require('fs');
fs.mkdirSync('newdir');
console.log(fs.statSync('newdir').isDirectory());
fs.writeFileSync('newdir/inner.txt', 'nested');
console.log(fs.readFileSync('newdir/inner.txt', 'utf8'));
