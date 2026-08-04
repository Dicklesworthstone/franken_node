const cluster = require('cluster');
if (cluster.isPrimary) {
  console.log('primary:true');
  const w = cluster.fork();
  w.on('exit', (code) => console.log('worker-exit:' + code));
} else {
  process.exit(3);
}
