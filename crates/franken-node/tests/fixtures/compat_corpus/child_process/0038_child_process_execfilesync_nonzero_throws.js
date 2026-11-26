const cp = require('child_process');
try {
  cp.execFileSync('sh', ['-c', 'exit 11']);
  console.log('no-throw');
} catch (e) {
  console.log('threw:' + (e instanceof Error));
  console.log('status:' + e.status);
}
