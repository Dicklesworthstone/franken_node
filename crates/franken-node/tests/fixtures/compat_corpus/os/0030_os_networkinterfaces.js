const os = require('os');
const lists = Object.values(os.networkInterfaces());
console.log(lists.every(Array.isArray));
console.log(lists.every((l) => l.every((i) => typeof i.address === 'string' && typeof i.family !== 'undefined')));
