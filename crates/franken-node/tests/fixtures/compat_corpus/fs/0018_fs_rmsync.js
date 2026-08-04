const fs = require('fs');
fs.mkdirSync('tree/leaf', { recursive: true });
fs.writeFileSync('tree/leaf/f.txt', 'x');
fs.rmSync('tree', { recursive: true });
console.log(fs.existsSync('tree'));
