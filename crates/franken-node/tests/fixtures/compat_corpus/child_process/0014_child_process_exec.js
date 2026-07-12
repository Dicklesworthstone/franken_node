const cp = require('child_process');
cp.exec('exit 9', (err, stdout) => {
  console.log('has-err:' + (err !== null));
  console.log('err-code:' + err.code);
  console.log('stdout-empty:' + (stdout.length === 0));
});
