const {EventEmitter} = require('events');
const e = new EventEmitter();
try {
  e.emit('error', new Error('boom'));
  console.log('no-throw');
} catch (err) {
  console.log('threw:' + err.message);
}
