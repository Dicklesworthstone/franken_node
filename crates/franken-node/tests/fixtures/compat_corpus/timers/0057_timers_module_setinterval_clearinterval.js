const timers = require('timers');
let count = 0;
const iv = timers.setInterval(() => {
  count++;
  if (count === 2) {
    timers.clearInterval(iv);
    console.log('module-interval:' + count);
  }
}, 5);
