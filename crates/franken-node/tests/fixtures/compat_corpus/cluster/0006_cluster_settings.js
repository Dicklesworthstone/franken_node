const cluster = require('cluster');
console.log('type:' + typeof cluster.settings);
console.log('keys:' + Object.keys(cluster.settings).length);
