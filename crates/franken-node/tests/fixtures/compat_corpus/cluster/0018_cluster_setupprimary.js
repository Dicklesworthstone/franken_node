const cluster = require('cluster');
cluster.setupPrimary({ args: ['--flag-a', '--flag-b'] });
console.log('is-array:' + Array.isArray(cluster.settings.args));
console.log('args:' + cluster.settings.args.join(','));
