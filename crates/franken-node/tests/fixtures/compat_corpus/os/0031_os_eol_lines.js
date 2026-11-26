const os = require('os');
console.log(os.EOL.charCodeAt(0));
console.log(os.EOL.includes('\r'));
const joined = ['alpha', 'beta', 'gamma'].join(os.EOL);
console.log(joined.split(os.EOL).join('|'));
