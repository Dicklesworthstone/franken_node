const cp = require('child_process');
const r = cp.spawnSync('printf', ['%s\n', 'a b', '$HOME', '"quoted"', ';true']);
const lines = r.stdout.toString().trim().split('\n');
console.log('args:' + lines.join('|'));
console.log('count:' + lines.length);
