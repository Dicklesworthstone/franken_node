const cp = require('child_process');
const c = cp.spawn('cat');
const before = c.killed;
let ok = false;
let after = false;
c.on('spawn', () => {
  ok = c.kill('SIGKILL');
  after = c.killed;
});
c.on('exit', (code, signal) => {
  console.log('before:' + before + ',ok:' + ok + ',after:' + after);
  console.log('code-null:' + (code === null));
  console.log('signal:' + signal);
});
