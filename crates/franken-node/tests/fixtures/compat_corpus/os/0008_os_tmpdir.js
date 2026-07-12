const os = require('os');
const path = require('path');
console.log(typeof os.tmpdir());
console.log(path.isAbsolute(os.tmpdir()));
console.log(os.tmpdir().length > 0);
