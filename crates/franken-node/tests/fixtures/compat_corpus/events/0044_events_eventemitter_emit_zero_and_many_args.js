const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('zero', function () {
  console.log('zero-argc:' + arguments.length);
});
e.on('many', function (a, b, c, d, f, g) {
  console.log('many-argc:' + arguments.length + ':' + [a, b, c, d, f, g].join('-'));
});
e.emit('zero');
e.emit('many', 1, 2, 3, 4, 5, 6);
