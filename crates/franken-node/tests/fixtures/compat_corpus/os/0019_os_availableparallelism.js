const os = require('os');
console.log(typeof os.availableParallelism());
console.log(os.availableParallelism() > 0);
console.log(Number.isInteger(os.availableParallelism()));
