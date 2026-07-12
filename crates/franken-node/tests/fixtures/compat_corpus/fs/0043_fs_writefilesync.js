const fs = require('fs');
fs.writeFileSync('app.txt', 'one');
fs.writeFileSync('app.txt', '+two', { flag: 'a' });
console.log(fs.readFileSync('app.txt', 'utf8'));
