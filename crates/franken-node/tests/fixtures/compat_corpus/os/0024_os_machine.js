const os = require('os');
console.log(typeof os.machine());
console.log(['x86_64', 'aarch64'].includes(os.machine()));
