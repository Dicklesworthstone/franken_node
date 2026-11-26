const path = require('path');
console.log(path.posix.relative('/a/b', '/a/c/d'));
console.log(path.posix.relative('/a/b/c', '/a/b'));
console.log(JSON.stringify(path.posix.relative('/a/b', '/a/b')));
