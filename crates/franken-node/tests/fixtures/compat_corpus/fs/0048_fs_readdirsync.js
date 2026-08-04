const fs = require('fs');
fs.mkdirSync('vacant');
console.log(fs.readdirSync('vacant').length);
