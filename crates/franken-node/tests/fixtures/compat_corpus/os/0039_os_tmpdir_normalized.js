const os = require('os');
const t = os.tmpdir();
console.log(t === os.tmpdir());
console.log(t.startsWith('/'));
console.log(t.length === 1 || !t.endsWith('/'));
