const fs = require('fs');
fs.writeFileSync('time.txt', 'x');
fs.utimesSync('time.txt', new Date(1000000000000), new Date(1000000000000));
console.log(fs.statSync('time.txt').mtime.getTime() === 1000000000000);
