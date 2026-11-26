const {EventEmitter} = require('events');
const e = new EventEmitter();
try {
  e.emit('error');
  console.log('no-throw');
} catch (err) {
  console.log('threw:' + (err instanceof Error));
}
