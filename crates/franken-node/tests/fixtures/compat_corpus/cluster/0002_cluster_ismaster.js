const cluster = require('cluster');
console.log('isMaster:' + cluster.isMaster);
console.log('eq-isPrimary:' + (cluster.isMaster === cluster.isPrimary));
