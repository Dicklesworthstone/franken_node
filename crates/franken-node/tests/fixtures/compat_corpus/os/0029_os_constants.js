const os = require('os');
console.log(typeof os.constants);
console.log(typeof os.constants.signals);
console.log(typeof os.constants.errno);
console.log(os.constants.priority.PRIORITY_NORMAL === 0);
