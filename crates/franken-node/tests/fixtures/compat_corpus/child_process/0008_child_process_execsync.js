const cp = require('child_process');
try {
  cp.execSync('exit 7');
  console.log('no-throw:true');
} catch (e) {
  console.log('threw:' + (e instanceof Error));
  console.log('status:' + e.status);
}
