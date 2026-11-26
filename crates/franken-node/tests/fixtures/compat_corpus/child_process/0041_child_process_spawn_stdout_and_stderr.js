const cp = require('child_process');
const c = cp.spawn('sh', ['-c', 'printf out-one; printf err-two >&2']);
let out = '';
let err = '';
c.stdout.on('data', (d) => { out += d.toString(); });
c.stderr.on('data', (d) => { err += d.toString(); });
c.on('close', (code) => {
  console.log('out:' + out);
  console.log('err:' + err);
  console.log('code:' + code);
});
