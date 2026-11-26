const cp = require('child_process');
cp.execFile('sh', ['-c', 'printf fail-err >&2; exit 5'], (err, stdout, stderr) => {
  console.log('has-err:' + (err !== null));
  console.log('code:' + err.code);
  console.log('stdout-empty:' + (stdout === ''));
  console.log('stderr:' + stderr);
});
