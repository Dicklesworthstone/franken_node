const timers = require('timers');
console.log(timers.setTimeout === setTimeout);
console.log(timers.clearTimeout === clearTimeout);
console.log(timers.setInterval === setInterval);
timers.setTimeout(() => {
  console.log('module-fired');
}, 10);
