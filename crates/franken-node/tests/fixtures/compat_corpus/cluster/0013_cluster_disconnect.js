const cluster = require('cluster');
cluster.disconnect(() => console.log('disconnected'));
console.log('called-first');
