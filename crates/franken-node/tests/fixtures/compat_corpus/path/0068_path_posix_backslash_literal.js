const path = require('path');
console.log(path.posix.basename('a\\b/c\\d.txt'));
console.log(path.posix.dirname('a\\b/c\\d.txt'));
console.log(path.posix.extname('a\\b.txt'));
console.log(path.posix.isAbsolute('\\foo'));
