const path = require('path');
console.log(path.posix.join('a', 'b', '..', 'c'));
console.log(path.posix.basename('/tmp/x.txt'));
console.log(path.posix.isAbsolute('/y'));
