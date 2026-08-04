const cp = require('child_process');
cp.exec('echo exec-cb-out', (err, stdout, stderr) => {
  console.log('err-null:' + (err === null));
  console.log('out:' + stdout.trim());
  console.log('stderr-empty:' + (stderr.length === 0));
});
