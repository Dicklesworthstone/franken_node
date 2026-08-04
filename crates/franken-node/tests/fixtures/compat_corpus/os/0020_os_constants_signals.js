const os = require('os');
console.log(os.constants.signals.SIGINT === 2);
console.log(typeof os.constants.signals.SIGINT);
