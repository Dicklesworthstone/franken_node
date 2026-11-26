const cluster = require('cluster');
const log = [];
cluster.on('tick', (n) => log.push('on:' + n));
cluster.once('tick', (n) => log.push('once:' + n));
cluster.emit('tick', 1);
cluster.emit('tick', 2);
console.log('events:' + log.join('|'));
