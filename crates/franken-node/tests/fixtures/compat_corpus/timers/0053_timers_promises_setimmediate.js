const tp = require('timers/promises');
(async () => {
  const v1 = await tp.setImmediate();
  const obj = { ok: true };
  const v2 = await tp.setImmediate(obj);
  console.log(v1 === undefined);
  console.log(v2 === obj);
})();
