const cp = require('child_process');
const c = cp.spawn('definitely-not-a-real-binary-batch-e');
c.on('error', (err) => {
  console.log('is-error:' + (err instanceof Error));
  console.log('code:' + err.code);
});
