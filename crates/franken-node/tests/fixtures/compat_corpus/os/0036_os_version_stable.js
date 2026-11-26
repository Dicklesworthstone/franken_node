const os = require('os');
const v1 = os.version();
const v2 = os.version();
console.log(v1 === v2);
console.log(v1.trim().length > 0);
console.log(!v1.includes('\0'));
