const cluster = require('cluster');
console.log('type:' + typeof cluster.SCHED_NONE);
console.log('distinct:' + (cluster.SCHED_NONE !== cluster.SCHED_RR));
