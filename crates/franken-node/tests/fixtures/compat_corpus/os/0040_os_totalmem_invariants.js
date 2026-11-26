const os = require('os');
const m1 = os.totalmem();
const m2 = os.totalmem();
console.log(Number.isInteger(m1));
console.log(m1 >= 1024 * 1024);
console.log(m1 === m2);
