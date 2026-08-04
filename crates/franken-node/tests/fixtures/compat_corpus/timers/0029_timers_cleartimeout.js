const timers = require('timers');
let fired = false;
const t = timers.setTimeout(() => { fired = true; }, 10);
timers.clearTimeout(t);
setTimeout(() => {
  console.log('module-clear-fired:' + fired);
}, 30);
