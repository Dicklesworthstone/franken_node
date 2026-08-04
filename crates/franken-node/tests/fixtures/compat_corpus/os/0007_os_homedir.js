const os = require('os');
const path = require('path');
console.log(typeof os.homedir());
console.log(path.isAbsolute(os.homedir()));
