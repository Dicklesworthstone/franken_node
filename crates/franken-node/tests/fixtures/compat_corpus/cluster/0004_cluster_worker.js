const cluster = require('cluster');
console.log('worker-undefined:' + (cluster.worker === undefined));
