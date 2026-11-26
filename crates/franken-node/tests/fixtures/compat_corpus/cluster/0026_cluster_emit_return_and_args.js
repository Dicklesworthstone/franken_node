const cluster = require('cluster');
const seen = [];
cluster.on('pair', (a, b) => seen.push('first:' + a + ':' + b));
cluster.on('pair', (a, b) => seen.push('second:' + a + ':' + b));
const hit = cluster.emit('pair', 'x', 9);
const miss = cluster.emit('unregistered', 1);
console.log('hit:' + hit + ',miss:' + miss);
console.log('seen:' + seen.join(','));
