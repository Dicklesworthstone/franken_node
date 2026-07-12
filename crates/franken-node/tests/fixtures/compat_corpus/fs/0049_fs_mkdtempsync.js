const fs = require('fs');
const d = fs.mkdtempSync('scratch-');
console.log(d.startsWith('scratch-'));
console.log(fs.statSync(d).isDirectory());
