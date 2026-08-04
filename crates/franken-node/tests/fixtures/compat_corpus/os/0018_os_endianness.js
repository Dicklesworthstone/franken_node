const os = require('os');
console.log(['BE', 'LE'].includes(os.endianness()));
console.log(os.endianness() === 'LE');
