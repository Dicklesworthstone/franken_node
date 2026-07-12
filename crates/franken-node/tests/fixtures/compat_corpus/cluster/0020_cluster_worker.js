const cluster = require('cluster');
console.log('Worker:' + typeof cluster.Worker);
console.log('negation:' + (cluster.isPrimary === !cluster.isWorker));
