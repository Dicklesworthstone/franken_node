const {Writable} = require('stream');
const w = new Writable({write(c, e, cb) { console.log('w:' + c.toString()); cb(); }});
w.cork();
w.write('a');
w.write('b');
console.log('corked-no-writes-yet');
process.nextTick(() => {
  w.uncork();
  console.log('after-uncork');
  w.end();
});
