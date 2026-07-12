const fs = require('fs');
fs.writeFileSync('old.txt', 'moved');
fs.renameSync('old.txt', 'new.txt');
console.log(fs.existsSync('old.txt'));
console.log(fs.readFileSync('new.txt', 'utf8'));
