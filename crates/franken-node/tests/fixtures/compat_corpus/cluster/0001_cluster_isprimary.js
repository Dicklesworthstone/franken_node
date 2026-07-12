const cluster = require('cluster');
console.log('isPrimary:' + cluster.isPrimary);
console.log('type:' + typeof cluster.isPrimary);
