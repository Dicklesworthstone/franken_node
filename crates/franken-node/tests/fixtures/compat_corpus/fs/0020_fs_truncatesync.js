const fs = require('fs');
fs.writeFileSync('t.txt', 'abcdef');
fs.truncateSync('t.txt', 3);
console.log(fs.readFileSync('t.txt', 'utf8'));
console.log(fs.statSync('t.txt').size);
