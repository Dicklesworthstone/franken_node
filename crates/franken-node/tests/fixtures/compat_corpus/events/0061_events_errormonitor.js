const {EventEmitter, errorMonitor} = require('events');
const e = new EventEmitter();
const log = [];
e.on(errorMonitor, (err) => {
  log.push('monitor:' + err.message);
});
try {
  e.emit('error', new Error('boom-mon'));
  log.push('no-throw');
} catch (err) {
  log.push('threw:' + err.message);
}
console.log(log.join('|'));
