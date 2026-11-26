const os = require('os');
const r1 = os.release();
const r2 = os.release();
console.log(r1 === r2);
console.log(/^\d+\.\d+/.test(r1));
console.log(!r1.includes('\0'));
