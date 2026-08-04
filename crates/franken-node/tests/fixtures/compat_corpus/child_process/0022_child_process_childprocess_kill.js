const cp = require('child_process');
const c = cp.spawn('sh', ['-c', 'sleep 5'], { stdio: 'ignore' });
c.on('spawn', () => c.kill());
c.on('exit', (code, signal) => {
  console.log('code:' + code);
  console.log('signal:' + signal);
});
