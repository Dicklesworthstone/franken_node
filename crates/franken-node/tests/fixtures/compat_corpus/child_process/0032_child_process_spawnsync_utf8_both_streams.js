const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'printf out-str; printf err-str >&2'], { encoding: 'utf8' });
console.log('types:' + typeof r.stdout + ',' + typeof r.stderr);
console.log('out:' + r.stdout);
console.log('err:' + r.stderr);
console.log('status:' + r.status);
