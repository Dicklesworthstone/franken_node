const cluster = require('cluster');
console.log('same-fn:' + (cluster.setupPrimary === cluster.setupMaster));
cluster.setupPrimary({ exec: 'base_worker.js', silent: true });
cluster.setupMaster({ execArgv: ['--trace-warnings'], silent: false });
console.log('exec-kept:' + cluster.settings.exec.endsWith('base_worker.js'));
console.log('silent-overwritten:' + cluster.settings.silent);
console.log('execArgv:' + cluster.settings.execArgv.join(','));
