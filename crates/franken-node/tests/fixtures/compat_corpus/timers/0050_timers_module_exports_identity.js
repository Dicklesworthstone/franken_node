const timers = require('timers');
const tp = require('timers/promises');
console.log(timers.clearInterval === clearInterval);
console.log(timers.setImmediate === setImmediate);
console.log(timers.clearImmediate === clearImmediate);
console.log(timers.promises === tp);
