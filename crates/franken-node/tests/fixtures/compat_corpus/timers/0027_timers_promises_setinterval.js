const tp = require('timers/promises');
(async () => {
  let n = 0;
  for await (const _ of tp.setInterval(10)) {
    n++;
    if (n === 2) break;
  }
  console.log('iterations:' + n);
})();
