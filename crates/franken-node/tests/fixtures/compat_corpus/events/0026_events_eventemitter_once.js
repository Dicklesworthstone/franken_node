const {EventEmitter} = require('events');
const e = new EventEmitter();
e.once('cfg', (host, port) => console.log(host + ':' + port));
e.emit('cfg', 'localhost', 8080);
e.emit('cfg', 'other', 9999);
