const cluster = require('cluster');
console.log('primary:' + (cluster.isPrimary === true));
console.log('master:' + (cluster.isMaster === true));
console.log('worker-flag:' + (cluster.isWorker === false));
console.log('worker-undef:' + (cluster.worker === undefined));
console.log('workers-plain:' + (typeof cluster.workers === 'object' && cluster.workers !== null && !Array.isArray(cluster.workers) && Object.keys(cluster.workers).length === 0));
