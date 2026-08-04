const fs = require('fs');
fs.writeFileSync('five.txt', 'hello');
console.log(fs.statSync('five.txt').size);
