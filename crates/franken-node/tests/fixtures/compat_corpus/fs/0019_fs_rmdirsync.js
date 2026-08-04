const fs = require('fs');
fs.mkdirSync('emptydir');
fs.rmdirSync('emptydir');
console.log(fs.existsSync('emptydir'));
