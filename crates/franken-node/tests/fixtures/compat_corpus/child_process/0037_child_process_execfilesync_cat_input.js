const cp = require('child_process');
const out = cp.execFileSync('cat', [], { input: 'via-execfilesync', encoding: 'utf8' });
console.log('type:' + typeof out);
console.log('out:' + out);
