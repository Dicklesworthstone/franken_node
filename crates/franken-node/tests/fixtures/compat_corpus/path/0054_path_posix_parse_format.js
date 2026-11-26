const path = require('path');
const parsed = path.posix.parse('/var/log/app.log');
console.log(JSON.stringify(parsed));
console.log(path.posix.format(parsed));
console.log(path.posix.format({ dir: '/opt', name: 'tool', ext: '.sh' }));
