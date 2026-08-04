const cluster = require('cluster');
console.log('fork:' + typeof cluster.fork);
