const os = require('os');
const path = require('path');
console.log(path.isAbsolute(os.devNull));
console.log(path.dirname(os.devNull));
console.log(path.basename(os.devNull));
