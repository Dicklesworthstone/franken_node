const cp = require('child_process');
const fs = require('fs');
fs.mkdirSync('batch_e_subdir', { recursive: true });
const r = cp.spawnSync('sh', ['-c', 'basename "$PWD"'], { cwd: 'batch_e_subdir' });
console.log('cwd-basename:' + r.stdout.toString().trim());
fs.rmSync('batch_e_subdir', { recursive: true, force: true });
