const os = require('os');
const c = os.cpus()[0];
console.log(typeof c.model);
console.log(typeof c.speed);
console.log(typeof c.times);
console.log(typeof c.times.user === 'number' && typeof c.times.idle === 'number');
