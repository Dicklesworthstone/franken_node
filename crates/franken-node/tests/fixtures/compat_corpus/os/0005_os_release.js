const os = require('os');
console.log(typeof os.release());
console.log(os.release().length > 0);
