const cp = require('child_process');
cp.execFile('echo', ['execfile-cb-out'], (err, stdout) => {
  console.log('err-null:' + (err === null));
  console.log('out:' + stdout.trim());
});
