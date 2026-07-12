const tp = require('timers/promises');
tp.setTimeout(10).then(() => {
  console.log('promise-timer-resolved');
});
console.log('scheduled');
