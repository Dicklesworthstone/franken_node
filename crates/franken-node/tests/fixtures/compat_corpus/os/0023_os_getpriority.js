const os = require('os');
console.log(typeof os.getPriority());
console.log(Number.isInteger(os.getPriority()));
console.log(os.getPriority() >= -20 && os.getPriority() <= 19);
