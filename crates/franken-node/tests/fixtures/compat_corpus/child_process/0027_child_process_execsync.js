const cp = require('child_process');
try {
  cp.execSync('echo before-fail; exit 3');
  console.log('no-throw:true');
} catch (e) {
  console.log('e-stdout:' + e.stdout.toString().trim());
  console.log('e-status:' + e.status);
}
