const tp = require('timers/promises');
(async () => {
  const marker = { tag: 'ok' };
  const [a, b] = await Promise.all([
    tp.setTimeout(5, marker),
    tp.setTimeout(10, 123),
  ]);
  console.log(a === marker);
  console.log(b);
})();
