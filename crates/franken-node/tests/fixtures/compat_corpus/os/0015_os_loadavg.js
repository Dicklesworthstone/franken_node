const os = require('os');
const la = os.loadavg();
console.log(Array.isArray(la));
console.log(la.length);
console.log(la.every((v) => typeof v === 'number' && v >= 0));
