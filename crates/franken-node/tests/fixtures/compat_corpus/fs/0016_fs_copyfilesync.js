const fs = require('fs');
fs.writeFileSync('src.txt', 'copy me');
fs.copyFileSync('src.txt', 'dst.txt');
console.log(fs.readFileSync('dst.txt', 'utf8'));
console.log(fs.readFileSync('src.txt', 'utf8'));
