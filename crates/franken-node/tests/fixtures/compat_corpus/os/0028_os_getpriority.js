const os = require('os');
console.log(os.getPriority(0) === os.getPriority(process.pid));
console.log(os.getPriority(0) === os.getPriority());
