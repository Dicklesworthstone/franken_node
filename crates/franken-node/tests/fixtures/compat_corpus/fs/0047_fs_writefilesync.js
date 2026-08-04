const fs = require('fs');
fs.writeFileSync('over.txt', 'original longer content');
fs.writeFileSync('over.txt', 'short');
console.log(fs.readFileSync('over.txt', 'utf8'));
