const os = require('os');
console.log(typeof os.freemem());
console.log(os.freemem() > 0);
console.log(os.freemem() <= os.totalmem());
