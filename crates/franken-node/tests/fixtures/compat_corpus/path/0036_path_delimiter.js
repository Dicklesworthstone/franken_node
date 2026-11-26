const path = require('path');
console.log(path.delimiter === path.posix.delimiter);
console.log(path.sep === path.posix.sep);
console.log('/usr/bin:/bin'.split(path.delimiter).join('|'));
console.log(path.win32.delimiter, path.win32.sep);
