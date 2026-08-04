const cluster = require('cluster');
console.log('type:' + typeof cluster.setupMaster);
cluster.setupMaster({ exec: 'legacy_worker.js' });
console.log('exec-ends:' + cluster.settings.exec.endsWith('legacy_worker.js'));
