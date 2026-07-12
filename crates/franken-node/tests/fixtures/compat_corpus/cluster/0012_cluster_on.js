const cluster = require('cluster');
const EventEmitter = require('events').EventEmitter;
console.log('instanceof-ee:' + (cluster instanceof EventEmitter));
console.log('on:' + typeof cluster.on);
console.log('once:' + typeof cluster.once);
console.log('emit:' + typeof cluster.emit);
