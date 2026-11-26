const tp = require('timers/promises');
(async () => {
  const got = [];
  for await (const val of tp.setInterval(5, 'pulse')) {
    got.push(val);
    if (got.length === 3) break;
  }
  console.log(got.length + ':' + got.join(','));
})();
