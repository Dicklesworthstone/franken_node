const {EventEmitter} = require('events');
const e = new EventEmitter();
for (const bad of [-1, NaN]) {
  try {
    e.setMaxListeners(bad);
    console.log(String(bad) + ':no-throw');
  } catch (err) {
    console.log(String(bad) + ':' + (err instanceof RangeError));
  }
}
console.log('unchanged:' + e.getMaxListeners());
