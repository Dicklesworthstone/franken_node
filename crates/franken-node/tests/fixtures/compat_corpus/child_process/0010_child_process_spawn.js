const cp = require('child_process');
const c = cp.spawn('echo', ['order-check']);
const events = [];
c.stdout.on('data', (d) => events.push('data:' + d.toString().trim()));
c.on('close', (code) => {
  events.push('close:' + code);
  console.log(events.join(','));
});
