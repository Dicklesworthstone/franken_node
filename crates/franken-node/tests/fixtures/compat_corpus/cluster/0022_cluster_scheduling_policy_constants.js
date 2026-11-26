const cluster = require('cluster');
console.log('policy-rr:' + (cluster.schedulingPolicy === cluster.SCHED_RR));
console.log('distinct:' + (cluster.SCHED_RR !== cluster.SCHED_NONE));
console.log('ints:' + (Number.isInteger(cluster.SCHED_RR) && Number.isInteger(cluster.SCHED_NONE)));
