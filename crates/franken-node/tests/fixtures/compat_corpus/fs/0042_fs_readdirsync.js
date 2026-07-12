const fs = require('fs');
fs.writeFileSync('.hidden', 'h');
fs.writeFileSync('visible.txt', 'v');
console.log(fs.readdirSync('.').sort().join(','));
