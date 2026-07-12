const fs = require('fs');
fs.writeFileSync('enc.txt', 'hello');
console.log(fs.readFileSync('enc.txt', 'base64'));
