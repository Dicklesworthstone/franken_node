const cp = require('child_process');
const out = cp.execFileSync('printf', ['%s', 'execfilesync-out']);
console.log('val:' + out.toString());
