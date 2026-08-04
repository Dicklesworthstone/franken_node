const cp = require('child_process');
const c = cp.spawn('false', [], { stdio: 'ignore' });
c.on('exit', (code, signal) => {
  console.log('code:' + code);
  console.log('signal-null:' + (signal === null));
});
