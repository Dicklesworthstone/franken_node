const cp = require('child_process');
const c = cp.spawn('echo', ['both-events']);
const order = [];
c.on('exit', (code) => order.push('exit:' + code));
c.on('close', (code) => {
  order.push('close:' + code);
  console.log(order.join(','));
});
