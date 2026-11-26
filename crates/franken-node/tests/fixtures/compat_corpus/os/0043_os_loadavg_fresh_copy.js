const os = require('os');
const a = os.loadavg();
const b = os.loadavg();
console.log(a !== b);
a[0] = -999;
const c = os.loadavg();
console.log(c.length === 3);
console.log(c.every((n) => Number.isFinite(n) && n >= 0));
