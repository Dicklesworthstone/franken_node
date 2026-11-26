const {EventEmitter} = require('events');
const e = new EventEmitter();
const out = [];
e.on('ord', () => out.push('on1'));
e.prependListener('ord', () => out.push('pre1'));
e.prependListener('ord', () => out.push('pre2'));
e.on('ord', () => out.push('on2'));
e.emit('ord');
console.log(out.join(','));
