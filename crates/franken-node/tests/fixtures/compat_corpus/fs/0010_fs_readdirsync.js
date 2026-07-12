const fs = require('fs');
fs.writeFileSync('c.txt', '3');
fs.writeFileSync('a.txt', '1');
fs.writeFileSync('b.txt', '2');
console.log(fs.readdirSync('.').sort().join(','));
