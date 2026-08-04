const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('t', function () { console.log('fn-this:' + (this === e)); });
e.on('t', () => console.log('arrow-this:' + (this === e)));
e.emit('t');
