const fs = require('fs');
fs.rmSync('not-there.txt', { force: true });
console.log('no-throw');
console.log(fs.existsSync('not-there.txt'));
