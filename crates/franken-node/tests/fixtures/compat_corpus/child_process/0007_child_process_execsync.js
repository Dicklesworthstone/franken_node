const cp = require('child_process');
const out = cp.execSync('echo exec-sync-out');
console.log('is-buffer:' + Buffer.isBuffer(out));
console.log('val:' + out.toString().trim());
