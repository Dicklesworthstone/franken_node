const cp = require('child_process');
const c = cp.spawn('true');
const events = [];
const pidOk = typeof c.pid === 'number' && c.pid > 0;
c.on('spawn', () => events.push('spawn'));
c.on('exit', () => events.push('exit'));
c.on('close', () => {
  events.push('close');
  console.log('pid-ok:' + pidOk);
  console.log('events:' + events.join(','));
});
