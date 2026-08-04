const fs = require('fs');
fs.mkdirSync('a/b/c', { recursive: true });
console.log(fs.existsSync('a/b/c'));
fs.writeFileSync('a/b/c/deep.txt', 'deep');
console.log(fs.readFileSync('a/b/c/deep.txt', 'utf8'));
