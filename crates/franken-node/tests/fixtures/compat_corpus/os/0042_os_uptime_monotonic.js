const os = require('os');
const u1 = os.uptime();
const u2 = os.uptime();
console.log(Number.isFinite(u1) && Number.isFinite(u2));
console.log(u1 >= 0);
console.log(u2 >= u1);
