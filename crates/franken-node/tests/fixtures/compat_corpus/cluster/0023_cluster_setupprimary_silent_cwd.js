const cluster = require('cluster');
const ret = cluster.setupPrimary({ silent: true, cwd: '/tmp' });
console.log('ret-undef:' + (ret === undefined));
console.log('silent:' + cluster.settings.silent);
console.log('cwd:' + cluster.settings.cwd);
