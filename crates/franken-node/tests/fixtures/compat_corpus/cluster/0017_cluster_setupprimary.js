const cluster = require('cluster');
cluster.setupPrimary({ exec: 'first_worker.js' });
cluster.setupPrimary({ args: ['--merged'] });
console.log('exec-kept:' + cluster.settings.exec.endsWith('first_worker.js'));
console.log('args:' + cluster.settings.args.join(','));
