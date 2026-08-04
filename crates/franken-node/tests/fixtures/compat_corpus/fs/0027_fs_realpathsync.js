const fs = require('fs');
fs.writeFileSync('real.txt', 'x');
const rp = fs.realpathSync('real.txt');
console.log(rp.endsWith('/real.txt'));
console.log(rp.split('/').pop());
