const os = require('os');
console.log(typeof os.totalmem());
console.log(os.totalmem() > 0);
console.log(Number.isFinite(os.totalmem()));
