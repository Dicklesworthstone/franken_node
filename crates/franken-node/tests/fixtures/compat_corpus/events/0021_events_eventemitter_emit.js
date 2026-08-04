const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('args', (a, b, c) => console.log(a + '|' + b + '|' + String(c)));
e.emit('args', 'x', 7, true);
e.emit('args', 'only');
