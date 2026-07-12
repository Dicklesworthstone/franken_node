const os = require('os');
console.log(typeof os.constants.errno.ENOENT);
console.log(os.constants.errno.ENOENT > 0);
console.log(os.constants.errno.ENOENT === 2);
