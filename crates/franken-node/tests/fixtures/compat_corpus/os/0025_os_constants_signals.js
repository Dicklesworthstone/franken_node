const os = require('os');
console.log(os.constants.signals.SIGHUP === 1);
console.log(os.constants.signals.SIGKILL === 9);
console.log(os.constants.signals.SIGTERM === 15);
