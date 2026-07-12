const cluster = require('cluster');
console.log('isWorker:' + cluster.isWorker);
console.log('type:' + typeof cluster.isWorker);
