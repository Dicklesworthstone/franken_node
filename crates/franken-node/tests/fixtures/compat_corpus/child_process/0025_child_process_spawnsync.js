const cp = require('child_process');
const r = cp.spawnSync('echo', ['arr-shape']);
console.log('output-len:' + r.output.length);
console.log('output1-eq-stdout:' + (r.output[1].toString() === r.stdout.toString()));
console.log('output1:' + r.output[1].toString().trim());
