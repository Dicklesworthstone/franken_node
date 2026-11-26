const os = require('os');
const arch = os.arch();
const mach = os.machine();
console.log(arch === os.arch());
console.log(mach === os.machine());
const pairOk = (arch === 'x64' && mach === 'x86_64') || (arch === 'arm64' && mach === 'aarch64');
console.log(pairOk);
