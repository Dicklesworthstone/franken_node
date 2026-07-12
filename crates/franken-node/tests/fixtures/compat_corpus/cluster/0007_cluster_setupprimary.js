const cluster = require('cluster');
cluster.setupPrimary({ exec: 'worker_batch_e.js' });
console.log('exec-set:' + (typeof cluster.settings.exec === 'string'));
console.log('exec-ends:' + cluster.settings.exec.endsWith('worker_batch_e.js'));
