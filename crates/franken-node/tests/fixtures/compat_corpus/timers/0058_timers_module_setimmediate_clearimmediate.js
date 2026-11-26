const timers = require('timers');
let cancelledRan = false;
const imCancel = timers.setImmediate(() => { cancelledRan = true; });
timers.clearImmediate(imCancel);
timers.setImmediate(() => {
  console.log('module-immediate-ok:cancelled=' + cancelledRan);
});
