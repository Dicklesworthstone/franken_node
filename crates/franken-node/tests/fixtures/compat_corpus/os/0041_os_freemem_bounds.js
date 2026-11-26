const os = require('os');
const free = os.freemem();
const total = os.totalmem();
console.log(Number.isFinite(free));
console.log(Number.isInteger(free));
console.log(free >= 0 && free <= total);
