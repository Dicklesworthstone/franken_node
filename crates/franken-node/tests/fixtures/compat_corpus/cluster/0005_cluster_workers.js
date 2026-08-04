const cluster = require('cluster');
console.log('type:' + typeof cluster.workers);
console.log('empty:' + (Object.keys(cluster.workers).length === 0));
