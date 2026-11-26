const cp = require('child_process');
const c = cp.spawn('sh', ['-c', 'exit 42']);
let exitInfo = '';
c.on('exit', (code, signal) => { exitInfo = code + ':' + (signal === null); });
c.on('close', (code, signal) => {
  console.log('exit:' + exitInfo);
  console.log('close:' + code + ':' + (signal === null));
});
