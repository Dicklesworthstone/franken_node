const tp = require('timers/promises');
tp.setTimeout(10, 'payload').then((v) => {
  console.log('value:' + v);
});
