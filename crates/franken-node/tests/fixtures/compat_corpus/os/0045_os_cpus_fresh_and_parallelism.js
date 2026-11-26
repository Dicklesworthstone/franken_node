const os = require('os');
const a = os.cpus();
const b = os.cpus();
const par = os.availableParallelism();
console.log(a !== b);
console.log(a.length === b.length);
console.log(par >= 1 && par <= a.length);
