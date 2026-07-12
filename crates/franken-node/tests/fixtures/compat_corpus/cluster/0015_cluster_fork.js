const cluster = require('cluster');
if (cluster.isPrimary) {
  const w = cluster.fork();
  cluster.on('online', () => console.log('online'));
  w.on('exit', (code) => console.log('exit:' + code));
} else {
  process.exit(0);
}
