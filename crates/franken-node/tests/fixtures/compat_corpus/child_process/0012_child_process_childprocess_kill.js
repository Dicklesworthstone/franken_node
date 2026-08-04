const cp = require('child_process');
const c = cp.spawn('sh', ['-c', 'sleep 5'], { stdio: 'ignore' });
c.on('spawn', () => {
  console.log('killed-before:' + c.killed);
  const ok = c.kill();
  console.log('kill-returned:' + ok);
  console.log('killed-after:' + c.killed);
});
c.on('exit', () => console.log('exited:true'));
