const os = require('os');
console.log(os.platform() === 'linux');
console.log(typeof os.platform());
console.log(os.platform() === process.platform);
