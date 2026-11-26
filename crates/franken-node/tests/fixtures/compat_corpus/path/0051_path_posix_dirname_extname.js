const path = require('path');
console.log(path.posix.dirname('/a/b/c.txt'));
console.log(path.posix.dirname('/only'));
console.log(path.posix.extname('/a/b/archive.tar.gz'));
console.log(JSON.stringify(path.posix.extname('/a.d/plain')));
