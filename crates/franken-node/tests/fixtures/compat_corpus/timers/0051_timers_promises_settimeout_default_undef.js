const tp = require('timers/promises');
(async () => {
  const val = await tp.setTimeout(5);
  console.log(val === undefined);
  console.log(typeof val);
})();
