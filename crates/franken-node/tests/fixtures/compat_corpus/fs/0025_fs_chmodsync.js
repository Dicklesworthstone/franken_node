const fs = require('fs');
fs.writeFileSync('perm.txt', 'x');
fs.chmodSync('perm.txt', 0o600);
console.log((fs.statSync('perm.txt').mode & 0o777).toString(8));
fs.chmodSync('perm.txt', 0o755);
console.log((fs.statSync('perm.txt').mode & 0o777).toString(8));
