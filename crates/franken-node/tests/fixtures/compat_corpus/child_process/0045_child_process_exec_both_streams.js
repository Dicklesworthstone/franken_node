const cp = require('child_process');
cp.exec('printf o1; printf e2 >&2', (err, stdout, stderr) => {
  console.log('err-null:' + (err === null));
  console.log('stdout:' + stdout);
  console.log('stderr:' + stderr);
});
