const cp = require('child_process');
const out = cp.execFileSync('printf', ['%s:%s', 'left', 'right'], { encoding: 'utf8' });
console.log('type:' + typeof out);
console.log('out:' + out);
