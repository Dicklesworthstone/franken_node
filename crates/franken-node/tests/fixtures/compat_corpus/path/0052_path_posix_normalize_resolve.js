const path = require('path');
console.log(path.posix.normalize('/a//b/../c/'));
console.log(path.posix.normalize('a/./b/../../c'));
console.log(path.posix.resolve('/a', 'b', '../c'));
console.log(path.posix.resolve('/a', '/b', 'c/'));
