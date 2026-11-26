const {EventEmitter} = require('events');
const e = new EventEmitter();
const log = [];
const later = () => log.push('later');
e.on('ev', () => {
  log.push('first');
  if (e.listenerCount('ev') === 1) e.on('ev', later);
});
e.emit('ev');
console.log('emit1:' + log.join(','));
e.emit('ev');
console.log('emit2:' + log.join(','));
