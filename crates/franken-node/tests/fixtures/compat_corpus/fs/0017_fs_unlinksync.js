const fs = require('fs');
fs.writeFileSync('gone.txt', 'x');
fs.unlinkSync('gone.txt');
console.log(fs.existsSync('gone.txt'));
