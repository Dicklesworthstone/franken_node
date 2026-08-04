const fs = require('fs');
fs.writeFileSync('here.txt', 'x');
console.log(fs.existsSync('here.txt'));
