const fs = require('fs');
fs.writeFileSync('hex.txt', 'hi!');
console.log(fs.readFileSync('hex.txt', 'hex'));
