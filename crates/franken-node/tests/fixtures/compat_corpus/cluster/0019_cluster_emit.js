const cluster = require('cluster');
cluster.on('batch-e-evt', (v) => console.log('got:' + v));
const had = cluster.emit('batch-e-evt', 42);
console.log('had-listener:' + had);
