const fs = require('fs');
fs.writeFileSync('lines.txt', 'alpha\nbeta\ngamma\n');
const lines = fs.readFileSync('lines.txt', 'utf8').split('\n');
console.log(lines.length);
console.log(lines[0] + '|' + lines[1] + '|' + lines[2]);
