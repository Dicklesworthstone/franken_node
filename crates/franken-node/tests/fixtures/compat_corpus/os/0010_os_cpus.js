const os = require('os');
const cpus = os.cpus();
console.log(Array.isArray(cpus));
console.log(cpus.length > 0);
