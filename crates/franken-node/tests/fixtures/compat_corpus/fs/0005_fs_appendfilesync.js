const fs = require('fs');
fs.writeFileSync('log.txt', 'first');
fs.appendFileSync('log.txt', '+second');
console.log(fs.readFileSync('log.txt', 'utf8'));
