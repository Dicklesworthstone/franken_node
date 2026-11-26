const {EventEmitter} = require('events');
class CounterEmitter extends EventEmitter {
  constructor(label) {
    super();
    this.label = label;
    this.count = 0;
  }
  bump(n) {
    this.count += n;
    this.emit('bumped', this.label, this.count);
  }
}
const c = new CounterEmitter('alpha');
console.log(c instanceof EventEmitter);
console.log(c instanceof CounterEmitter);
c.on('bumped', function (lbl, cnt) {
  console.log((this === c) + ':' + lbl + ':' + cnt);
});
c.bump(3);
c.bump(4);
