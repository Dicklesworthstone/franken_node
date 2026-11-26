const cluster = require('cluster');
cluster.setupPrimary({ exec: 'keep_me.js', silent: true });
cluster.setupPrimary();
cluster.setupPrimary(undefined);
console.log('exec-intact:' + cluster.settings.exec.endsWith('keep_me.js'));
console.log('silent-intact:' + cluster.settings.silent);
