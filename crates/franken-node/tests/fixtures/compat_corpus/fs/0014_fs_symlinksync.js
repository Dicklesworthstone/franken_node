const fs = require('fs');
fs.writeFileSync('target.txt', 'via link');
fs.symlinkSync('target.txt', 'link');
console.log(fs.lstatSync('link').isSymbolicLink());
console.log(fs.statSync('link').isFile());
console.log(fs.readlinkSync('link'));
console.log(fs.readFileSync('link', 'utf8'));
