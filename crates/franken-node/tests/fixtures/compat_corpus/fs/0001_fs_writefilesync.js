const fs = require('fs');
fs.writeFileSync('greet.txt', 'hello world');
console.log(fs.readFileSync('greet.txt', 'utf8'));
