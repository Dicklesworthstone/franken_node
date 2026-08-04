const os = require('os');
console.log(['x64', 'arm64'].includes(os.arch()));
console.log(typeof os.arch());
