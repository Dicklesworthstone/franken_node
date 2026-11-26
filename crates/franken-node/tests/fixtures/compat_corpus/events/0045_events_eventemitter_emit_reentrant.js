const {EventEmitter} = require('events');
const e = new EventEmitter();
const trace = [];
e.on('inner', (v) => trace.push('inner:' + v));
e.on('outer', () => {
  trace.push('outer-start');
  e.emit('inner', 99);
  trace.push('outer-end');
});
e.emit('outer');
console.log(trace.join(','));
