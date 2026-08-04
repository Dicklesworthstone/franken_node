const fs = require('fs');
fs.writeFileSync('acc.txt', 'x');
fs.accessSync('acc.txt', fs.constants.F_OK);
console.log('accessible');
