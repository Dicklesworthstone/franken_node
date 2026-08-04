const fs = require('fs');
fs.writeFileSync('empty.txt', '');
console.log(fs.readFileSync('empty.txt', 'utf8').length);
console.log(fs.statSync('empty.txt').size);
